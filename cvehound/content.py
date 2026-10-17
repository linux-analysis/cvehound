"""Out-of-band detection content: resolution and installation.

Detection content (the rules in cve/ and the metadata blob in data/) ships as
a baseline inside the installed package and can be refreshed without a tool
release by `cvehound update`.  Updates are installed into an XDG data
directory (the "overlay") and, when present and valid, wholly replace the
packaged content.  The installed package itself is never written to.

Overlay layout:

    $XDG_DATA_HOME/cvehound/content/
        current -> releases/<content_id>     # symlink, swapped atomically
        releases/<content_id>/
            manifest.json
            cve/CVE-*.cocci ...
            data/kernel_cves.json.gz

A content set is distributed as a standalone manifest.json plus a tarball of
cve/ and data/.  The manifest is fetched first (it carries the tarball's
sha256 and one sha256 per file); the tarball is never extracted directly --
each member is validated against the manifest and written out by hand, and
the verified manifest is stored next to the result.
"""

import contextlib
import dataclasses
import functools
import hashlib
import io
import json
import logging
import os
import shutil
import tarfile
import tempfile
import urllib.request
from importlib.resources import files
from typing import Any

# The one compatibility lever between a released package and the rolling content
# it downloads.  validate_manifest() demands exact equality and fetch_manifest()
# applies it *before* the tarball is pulled, so an older cvehound offered content
# it cannot run declines it with an actionable message instead of installing it
# and then failing on every rule.  Bump it for anything a released cvehound could
# not execute -- not only a layout change.  2: rules no longer declare
# "virtual detect", which a client still passing -D detect rejects with exit 255.
FORMAT_VERSION = 2
DEFAULT_BASE = 'https://github.com/linux-analysis/cvehound/releases/download/content-latest'
MANIFEST_NAME = 'manifest.json'
METADATA_NAME = 'data/kernel_cves.json.gz'
CONTENT_ID_NAME = 'data/content_id'
RULE_SUFFIXES = ('.cocci', '.grep')
KEEP_RELEASES = 2
DOWNLOAD_TIMEOUT = 60


class ContentError(Exception):
    """A content set could not be fetched, verified, or installed."""


@dataclasses.dataclass
class ContentSource:
    rules_dir: str
    metadata_path: str | None
    source: str  # 'overlay' or 'packaged'
    content_id: str | None = None
    source_commit: str | None = None
    metadata_generated: str | None = None


def get_content_home() -> str | None:
    """The overlay directory, or None when the overlay is disabled."""
    home = os.environ.get('CVEHOUND_CONTENT')
    if home == 'none':
        return None
    if not home:
        xdg = os.environ.get('XDG_DATA_HOME') or os.path.join(
            os.path.expanduser('~'), '.local', 'share'
        )
        home = os.path.join(xdg, 'cvehound', 'content')
    return home


def _is_editable_install() -> bool:
    """Tell whether cvehound runs from a git checkout (editable install).

    Under PEP 660 editable installs the package's dist metadata lives in
    site-packages, so ask the imported module itself: its source sits in the
    checkout, right next to the repository's .git.  This is also independent
    of the current working directory.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.exists(os.path.join(root, '.git'))


def repo_content_wins() -> bool:
    """Tell whether the repo's own content outranks the overlay: an editable
    (git checkout) install with no explicit CVEHOUND_CONTENT setting."""
    return not os.environ.get('CVEHOUND_CONTENT') and _is_editable_install()


def load_manifest(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding='utf-8') as fh:
            manifest = json.load(fh)
    except OSError as err:
        raise ContentError(f'cannot read manifest: {err}') from err
    except ValueError as err:
        raise ContentError(f'cannot parse manifest: {err}') from err
    return validate_manifest(manifest)


def validate_manifest(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ContentError('manifest is not a JSON object')
    fmt = manifest.get('format_version')
    if fmt != FORMAT_VERSION:
        # Which side is behind decides what the user can do about it, and both
        # directions are reachable: an old cvehound meeting content built after a
        # bump, and a fresh cvehound meeting the rolling release before it catches
        # up. One message for both would send half of them to the wrong fix.
        if isinstance(fmt, int) and fmt < FORMAT_VERSION:
            raise ContentError(
                f'content format {fmt} predates this cvehound (expects {FORMAT_VERSION}); '
                'the published content has not caught up yet'
            )
        raise ContentError(f'unknown content format {fmt!r}: a newer cvehound is required')
    if not isinstance(manifest.get('content_id'), str) or not manifest['content_id']:
        raise ContentError('manifest has no content_id')
    rules = manifest.get('rules')
    if not isinstance(rules, dict) or not isinstance(rules.get('files'), dict):
        raise ContentError('manifest has no rules file list')
    metadata = manifest.get('metadata')
    if not isinstance(metadata, dict) or not isinstance(metadata.get('sha256'), str):
        raise ContentError('manifest has no metadata description')
    return manifest


def _overlay_source(release: str) -> ContentSource:
    manifest = load_manifest(os.path.join(release, MANIFEST_NAME))
    rules_dir = os.path.join(release, 'cve')
    if not os.path.isdir(rules_dir):
        raise ContentError('no cve/ directory in the overlay release')
    metadata_path = os.path.join(release, METADATA_NAME)
    if not os.path.isfile(metadata_path):
        raise ContentError('no metadata file in the overlay release')
    return ContentSource(
        rules_dir=rules_dir,
        metadata_path=metadata_path,
        source='overlay',
        content_id=manifest['content_id'],
        source_commit=manifest.get('source_commit'),
        metadata_generated=manifest['metadata'].get('generated'),
    )


def _packaged_source() -> ContentSource:
    base = files('cvehound')
    rules_dir = str(base.joinpath('cve'))
    metadata_path: str | None = str(base.joinpath(METADATA_NAME))
    if not os.path.isfile(metadata_path):
        metadata_path = None
    content_id = None
    stamp = base.joinpath(CONTENT_ID_NAME)
    with contextlib.suppress(OSError):
        content_id = stamp.read_text(encoding='utf-8').strip() or None
    return ContentSource(
        rules_dir=rules_dir,
        metadata_path=metadata_path,
        source='packaged',
        content_id=content_id,
    )


def _current_release(home: str) -> str:
    """The release directory the overlay's `current` symlink points at."""
    return os.path.realpath(os.path.join(home, 'current'))


def resolve_content() -> ContentSource:
    """Pick the content set to scan with: a valid overlay, else the packaged baseline.

    In an editable install the repository's own content always wins so that
    rules under development are the rules that run; an explicitly set
    CVEHOUND_CONTENT still selects the overlay there.

    The result is memoized on its actual inputs: the overlay symlink is
    resolved exactly once per process, so every consumer (rule discovery,
    metadata lookup, the report's content identity) sees the same release
    even if a concurrent `cvehound update` swaps it mid-run.
    """
    home = None if repo_content_wins() else get_content_home()
    return _resolve_content_cached(home)


@functools.cache
def _resolve_content_cached(home: str | None) -> ContentSource:
    if home:
        release = _current_release(home)
        if os.path.isdir(release):
            try:
                return _overlay_source(release)
            except ContentError as err:
                logging.warning(
                    'Ignoring content overlay at %s (%s); using packaged content', release, err
                )
    return _packaged_source()


def _read_resource(base: str, name: str) -> bytes:
    """Read a file from a base location: a local directory or an URL prefix."""
    if '://' not in base:
        path = os.path.join(base, name)
        try:
            with open(path, 'rb') as fh:
                return fh.read()
        except OSError as err:
            raise ContentError(f'cannot read {path}: {err}') from err
    url = base.rstrip('/') + '/' + name
    try:
        with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT) as resp:
            return resp.read()
    except OSError as err:
        raise ContentError(f'cannot download {url}: {err}') from err


def fetch_manifest(base: str = DEFAULT_BASE) -> dict[str, Any]:
    raw = _read_resource(base, MANIFEST_NAME)
    try:
        manifest = json.loads(raw)
    except ValueError as err:
        raise ContentError(f'cannot parse manifest from {base}: {err}') from err
    manifest = validate_manifest(manifest)
    tarball = manifest.get('tarball')
    if not isinstance(tarball, dict) or not tarball.get('name') or not tarball.get('sha256'):
        raise ContentError('manifest has no tarball description')
    return manifest


def installed_manifest(home: str | None = None) -> dict[str, Any] | None:
    """The manifest of the currently installed overlay, or None."""
    if home is None:
        home = get_content_home()
    if not home:
        return None
    release = _current_release(home)
    if not os.path.isdir(release):
        return None
    try:
        return load_manifest(os.path.join(release, MANIFEST_NAME))
    except ContentError:
        return None


def _expected_files(manifest: dict[str, Any]) -> dict[str, str]:
    expected = dict(manifest['rules']['files'])
    expected[METADATA_NAME] = manifest['metadata']['sha256']
    return expected


def _extract_verified(tar_bytes: bytes, manifest: dict[str, Any], dest: str) -> None:
    """Write the tarball's members into dest, each verified against the manifest.

    Nothing is trusted from the archive: member names must appear in the
    manifest and every payload must match its sha256.
    """
    expected = _expected_files(manifest)
    written: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:gz') as tar:
            for member in tar:
                if member.isdir():
                    continue
                name = member.name
                while name.startswith('./'):
                    name = name[2:]
                if not member.isfile():
                    raise ContentError(f'unexpected member type in tarball: {name}')
                if name.startswith('/') or '\\' in name or '..' in name.split('/'):
                    raise ContentError(f'unsafe path in tarball: {name}')
                if name == MANIFEST_NAME:
                    continue  # the verified standalone manifest is written instead
                if name not in expected:
                    raise ContentError(f'file not listed in the manifest: {name}')
                reader = tar.extractfile(member)
                if reader is None:
                    raise ContentError(f'cannot read member: {name}')
                data = reader.read()
                if hashlib.sha256(data).hexdigest() != expected[name]:
                    raise ContentError(f'checksum mismatch: {name}')
                path = os.path.join(dest, name)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, 'wb') as fh:
                    fh.write(data)
                written.add(name)
    except (OSError, tarfile.TarError) as err:
        raise ContentError(f'cannot unpack content tarball: {err}') from err
    missing = sorted(set(expected) - written)
    if missing:
        raise ContentError(
            'files listed in the manifest are missing from the tarball: ' + ', '.join(missing)
        )


def _swap_current(home: str, target: str) -> None:
    link = os.path.join(home, 'current')
    tmp_link = link + '.' + str(os.getpid())
    os.symlink(os.path.relpath(target, home), tmp_link)
    os.replace(tmp_link, link)


def _prune_releases(home: str) -> None:
    releases = os.path.join(home, 'releases')
    current = _current_release(home)
    entries = []
    try:
        names = os.listdir(releases)
    except OSError:
        return
    for name in names:
        path = os.path.join(releases, name)
        if os.path.realpath(path) == current or not os.path.isdir(path):
            continue
        entries.append(path)
    entries.sort(key=os.path.getmtime, reverse=True)
    for path in entries[KEEP_RELEASES - 1 :]:
        shutil.rmtree(path, ignore_errors=True)


def install_content(base: str = DEFAULT_BASE, force: bool = False) -> tuple[str, bool]:
    """Fetch, verify, and atomically install a content set into the overlay.

    Returns (content_id, updated): updated is False when the overlay already
    holds that content set.  The previous release is left untouched until the
    new one is completely verified and in place.
    """
    home = get_content_home()
    if not home:
        raise ContentError('the content overlay is disabled (CVEHOUND_CONTENT=none)')
    manifest = fetch_manifest(base)
    content_id = manifest['content_id']
    installed = installed_manifest(home)
    if not force and installed and installed.get('content_id') == content_id:
        return content_id, False

    tar_bytes = _read_resource(base, manifest['tarball']['name'])
    digest = hashlib.sha256(tar_bytes).hexdigest()
    if digest != manifest['tarball']['sha256']:
        raise ContentError(
            f'tarball checksum mismatch: expected {manifest["tarball"]["sha256"]}, got {digest}'
        )

    releases = os.path.join(home, 'releases')
    os.makedirs(releases, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix='.tmp-', dir=releases)
    old = None
    try:
        _extract_verified(tar_bytes, manifest, tmp)
        with open(os.path.join(tmp, MANIFEST_NAME), 'w', encoding='utf-8') as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
        target = os.path.join(releases, content_id)
        if os.path.isdir(target):
            # Move the existing copy aside instead of deleting it in place:
            # on a --force reinstall it is the release `current` points to,
            # and destroying it before the new one is in place would leave a
            # dangling overlay if the rename fails or the process dies here.
            old = os.path.join(releases, f'.old-{os.getpid()}-{content_id}')
            shutil.rmtree(old, ignore_errors=True)
            os.rename(target, old)
        try:
            os.rename(tmp, target)
        except BaseException:
            if old is not None:
                os.rename(old, target)
                old = None
            raise
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    _swap_current(home, target)
    if old is not None:
        shutil.rmtree(old, ignore_errors=True)
    _prune_releases(home)
    _resolve_content_cached.cache_clear()
    return content_id, True


def check_content(base: str = DEFAULT_BASE) -> tuple[str | None, str]:
    """Compare the installed overlay with what the base location offers.

    Returns (installed_id, available_id); installed_id is None when no
    overlay is installed.
    """
    manifest = fetch_manifest(base)
    installed = installed_manifest()
    installed_id = installed.get('content_id') if installed else None
    return installed_id, manifest['content_id']
