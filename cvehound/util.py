import contextlib
import functools
import gzip
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
from configparser import ConfigParser
from datetime import UTC, datetime
from importlib.metadata import distribution, version
from typing import Any

from cvehound.content import RULE_SUFFIXES, resolve_content
from cvehound.exception import PcreGrepNotFound, SpatchNotFound

# The top-level Makefile's ARCH -> SRCARCH mapping: which arch/<dir>
# the sources for a given ARCH= value actually live in.
SRCARCH = {
    'i386': 'x86',
    'x86_64': 'x86',
    'sparc32': 'sparc',
    'sparc64': 'sparc',
    'parisc64': 'parisc',
    'sh64': 'sh',
    'tilepro': 'tile',
    'tilegx': 'tile',
}


def get_srcarch(arch: str) -> str:
    return SRCARCH.get(arch, arch)


def killpg(pid: int) -> None:
    """SIGKILL a whole process group, tolerating one that is already gone."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGKILL)


def get_cache_dir() -> str:
    """Where cvehound keeps regenerable state: $CVEHOUND_CACHE, else XDG."""
    cache = os.environ.get('CVEHOUND_CACHE')
    if not cache:
        xdg = os.environ.get('XDG_CACHE_HOME') or os.path.join(os.path.expanduser('~'), '.cache')
        cache = os.path.join(xdg, 'cvehound')
    return cache


def bundled_spatch() -> str | None:
    """The realpath of the bundled cvehound-spatch binary, or None.

    FileNotFoundError is not hypothetical: spatch_path() raises it when the
    package is imported from a source checkout, where the Python API exists but
    no binary was ever packed.
    """
    try:
        import cvehound_spatch  # ty: ignore[unresolved-import]  # optional sidecar package

        return os.path.realpath(cvehound_spatch.spatch_path())
    except (ImportError, FileNotFoundError, OSError):
        return None


def spatch_features(spatch: str) -> frozenset[str]:
    """What this spatch can do beyond the stock command line.

    The bundled build answers from its wheel, which records what make_wheel.py
    probed the binary for. Any other binary is asked `spatch --features`: a
    build that knows the option lists its tokens one per line, and one that
    does not rejects it with exit 2 -- the answer "nothing". --zygote itself is
    dispatched before spatch parses argv and the version banner says nothing of
    it, so before --features only the wheel could answer.
    """
    bundled = bundled_spatch()
    if bundled is not None and os.path.realpath(spatch) == bundled:
        import cvehound_spatch  # ty: ignore[unresolved-import]  # optional sidecar package

        return frozenset(getattr(cvehound_spatch, 'FEATURES', frozenset()))
    return _probe_features(os.path.realpath(spatch))


@functools.cache
def _probe_features(spatch: str) -> frozenset[str]:
    try:
        run = subprocess.run(
            [spatch, '--features'],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors='replace',
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return frozenset()
    return frozenset(run.stdout.split()) if run.returncode == 0 else frozenset()


def resolve_zygote(mode: str, spatch: str) -> bool:
    """Whether to run spatch as a fork-per-request server.

    'auto' means "wherever it works": the bundled build that advertises it.
    'on' is a demand, not a hint -- it stays true even for a spatch that cannot
    do it, so the run fails loudly instead of quietly performing differently
    from what was asked.
    """
    if mode == 'off':
        return False
    if mode == 'on':
        return True
    return 'zygote' in spatch_features(spatch)


def astcache_dir(setting: str | None, spatch: str | None = None) -> str | None:
    """The parsed-C AST cache directory, or None when caching is off.

    Single source of truth for the setting: the sandbox grant and the
    --cache-prefix argument must be the same path, and the failure mode of
    disagreeing is silent -- spatch cannot write the cache and the scan just
    never speeds up. Created here so every reader sees a usable directory.

    The default path is namespaced by the spatch it was built with, and that is
    load-bearing rather than tidy: entries are marshalled OCaml values carrying
    no type tag, so handing one build's entry to another build is undefined
    behaviour -- a wrong verdict or a crash, not an exception -- and nothing in
    coccinelle's own cache key would catch it.
    """
    if not setting or setting in ('none', 'off'):
        return None
    if setting == 'auto':
        if spatch is None:
            raise ValueError('the default AST cache path needs the spatch it belongs to')
        ident = hashlib.sha256(spatch_identity(spatch).encode()).hexdigest()[:16]
        setting = os.path.join(get_cache_dir(), 'ast', ident)
    astcache = os.path.abspath(setting)
    os.makedirs(astcache, exist_ok=True)
    return astcache


def astcache_prune(astcache: str, limit: int) -> int:
    """Evict least-recently-used entries until the cache fits. Returns bytes freed.

    cvehound has to own this because coccinelle will not: it never prunes, and
    its own --cache-limit is a flush-all that additionally walks the whole cache
    on every miss. An entry is the (.ast_raw, .depend_raw) pair, dropped
    together -- a dependency file outliving its value would be read as a valid
    entry pointing at nothing. The dependency therefore goes first, so a reader
    racing the prune sees a miss and re-parses: the cache is pruned while scans
    are running, not only between them.
    """
    entries = []
    for root, _dirs, files in os.walk(astcache):
        for name in files:
            if not name.endswith('.ast_raw'):
                continue
            value = os.path.join(root, name)
            depend = value[: -len('.ast_raw')] + '.depend_raw'
            try:
                stat = os.stat(value)
            except OSError:
                continue
            size = stat.st_size + (os.path.getsize(depend) if os.path.exists(depend) else 0)
            entries.append((stat.st_atime, size, value, depend))
    total = sum(size for _, size, _, _ in entries)
    if total <= limit:
        return 0
    freed = 0
    for _atime, size, value, _depend in sorted(entries):
        if total - freed <= limit:
            break
        _drop_entry(value[: -len('.ast_raw')])
        freed += size
    return freed


def _drop_entry(stem: str) -> None:
    """Remove one entry, the dependency first: a reader racing the removal then
    sees a miss and re-parses, never a dependency pointing at nothing."""
    for path in (stem + '.depend_raw', stem + '.ast_raw'):
        with contextlib.suppress(OSError):
            os.unlink(path)


def astcache_clear(astcache: str) -> int:
    """Drop every entry, leaving the directory. Returns bytes freed."""
    return astcache_prune(astcache, 0)


def astcache_evict(astcache: str, files: list[str]) -> None:
    """Drop the entries for these source files.

    coccinelle names an entry after the path it parsed, absolute and with the
    leading '/' dropped, under the prefix (cache_computation_robust2 in commons/
    common.ml). A torn entry it neither re-parses nor removes, so it costs the
    file on every scan sharing the cache until the source changes; this is the
    eviction coccinelle does not do.
    """
    for file in files:
        _drop_entry(os.path.join(astcache, os.path.abspath(file).lstrip('/')))


def spatch_identity(spatch: str) -> str:
    """A string that changes whenever the binary's marshalled types might.

    The first --version line is not enough on its own: a distro build and the
    bundled one report the same "spatch version 1.3.2 compiled with OCaml ...",
    while differing in patches and configure flags. The rest of the banner
    carries those flags.
    """
    try:
        banner = subprocess.check_output(
            [spatch, '--version'], stderr=subprocess.DEVNULL, universal_newlines=True
        ).strip()
    except (OSError, subprocess.SubprocessError):
        banner = ''
    return '\x00'.join((os.path.realpath(spatch), banner))


def get_config_data(path: str) -> dict[str, str]:
    with open(path) as fh:
        ver_pattern = re.compile(r'# Linux/(\S+)\s+(\S+)\s+Kernel Configuration')
        for line in fh:
            res = ver_pattern.match(line)
            if res:
                return {'arch': res.group(1), 'version': res.group(2)}
    return {}


def get_kernel_version(path: str) -> dict[str, str]:
    with open(os.path.join(path, 'Makefile')) as fh:
        makefile = fh.read()
    ver: dict[str, str] = {}
    for key in ['version', 'patchlevel', 'sublevel', 'extraversion', 'name']:
        res = re.search('^' + key.upper() + r'[ \t]*=[ \t]*(.*)[ \t]*$', makefile, re.MULTILINE)
        if res:
            ver[key] = res.group(1)
        else:
            ver[key] = ''
    ver['full'] = (
        '.'.join([ver['version'], ver['patchlevel'], ver['sublevel']]) + ver['extraversion']
    )
    return ver


def get_cvehound_version() -> str:
    pkg_version = version('cvehound')
    dist = distribution('cvehound')
    location = str(dist.locate_file(''))

    if not os.path.exists(os.path.join(location, '.git')):
        return pkg_version

    try:
        desc = ['git', 'describe', '--tags', '--dirty']
        pkg_version = subprocess.check_output(
            desc, cwd=location, stderr=subprocess.DEVNULL, universal_newlines=True
        ).strip()
    except Exception:
        pass

    return pkg_version


@functools.cache
def pcre_grep() -> str:
    """The grep to run .grep rules with: the first one on PATH that has -P.

    Rules are written as PCRE, so -P is not an optimisation, it is the dialect.
    Probed rather than assumed, because having GNU grep is not enough -- -P is
    a build option (--with-pcre) and a grep built without it rejects the flag
    exactly like BSD grep does. Empty stdin makes the probe pure: 1 is
    "supported, no match", 2 is "no such option".

    Cached: the answer cannot change within a process, and check_cve() would
    otherwise re-probe once per pattern per rule, in every pool worker.
    """
    for name in ('grep', 'ggrep'):
        path = shutil.which(name)
        if path is None:
            continue
        run = subprocess.run(
            [path, '-qP', 'x'], input='', capture_output=True, text=True, check=False
        )
        if run.returncode < 2:
            return path
    raise PcreGrepNotFound(
        'no grep with -P (PCRE) support found on PATH; .grep rules cannot be '
        'checked. On macOS the system grep is BSD grep, which has no -P: '
        'install GNU grep with `brew install grep` (it lands as ggrep).'
    )


def find_spatch(explicit: str | None = None) -> str:
    """Resolve the spatch binary to run.

    Precedence: an explicit path/name (--spatch, config file) -> the
    CVEHOUND_SPATCH environment variable -> the bundled cvehound-spatch
    package -> whatever is on PATH.

    An explicitly named binary that does not resolve is an error, never a
    silent fallback; an implicit source that does not resolve falls through
    to the next one. Failure to resolve anything at all raises
    SpatchNotFound, so callers never have to handle a None.
    """

    def resolve(name: str, origin: str) -> str:
        path = shutil.which(name)
        if path is None:
            raise SpatchNotFound(f'spatch not found at {name!r} (from {origin})')
        return path

    if explicit:
        return resolve(explicit, '--spatch')
    env = os.environ.get('CVEHOUND_SPATCH')
    if env:
        return resolve(env, '$CVEHOUND_SPATCH')
    try:
        import cvehound_spatch  # ty: ignore[unresolved-import]  # optional sidecar package

        # The sidecar is not an explicit choice, so a package whose binary is
        # missing must fall through to PATH rather than hand back a path that
        # only fails later, inside subprocess.
        bundled = shutil.which(str(cvehound_spatch.spatch_path()))
        if bundled:
            return bundled
    except ImportError:
        pass
    found = shutil.which('spatch')
    if found is None:
        raise SpatchNotFound(
            "spatch not found: install coccinelle, or pip install 'cvehound[spatch]' "
            'to get a prebuilt one'
        )
    return found


def get_spatch_version(spatch: str) -> int:
    version_output = (
        subprocess.check_output(
            [spatch, '--version'], stderr=subprocess.DEVNULL, universal_newlines=True
        )
        .strip()
        .split('\n')[0]
    )
    res = re.match(r'spatch\s+version\s+([\d.]+)', version_output)
    if res is None:
        raise RuntimeError('Could not parse spatch version')
    version_string = res.group(1)
    nums = version_string.count('.')
    if nums == 1:
        version_string += '.0'
    return int(version_string.replace('.', ''))


def get_rule_cves() -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    known: dict[str, str] = {}
    assigned: dict[str, str] = {}
    disputed: dict[str, str] = {}
    cve_dir = resolve_content().rules_dir
    for root, _dirs, file_list in os.walk(cve_dir):
        rel = os.path.relpath(root, cve_dir)
        is_disputed = rel.split(os.sep)[0] == 'disputed'
        for cve in file_list:
            if not cve.endswith(RULE_SUFFIXES):
                continue
            path = os.path.join(root, cve)
            name = cve.removesuffix('.grep').removesuffix('.cocci')
            known[name] = path
            if is_disputed:
                disputed[name] = path
            else:
                assigned[name] = path
    return (known, assigned, disputed)


def resolve_metadata_path(path: str | None = None) -> str | None:
    """Resolve the metadata blob to use: the explicit path, $CVEHOUND_METADATA,
    the content overlay, then the packaged default; None when nothing exists."""
    if not path:
        path = os.environ.get('CVEHOUND_METADATA')
    if path:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Can't find metadata file {path}")
        if not path.endswith('.gz'):
            raise ValueError(f'Metadata file {path} is not a gz archive')
        return path
    return resolve_content().metadata_path


def latest_fix_date(metadata: dict[str, Any]) -> int:
    """The newest fix_date in a metadata blob: its effective generation date."""
    return max((info.get('fix_date', 0) for info in metadata.values()), default=0)


def fix_date_str(timestamp: int) -> str:
    """Render a fix_date timestamp the one way it appears everywhere."""
    return datetime.fromtimestamp(timestamp, tz=UTC).strftime('%Y-%m-%d')


def get_cves_metadata(path: str | None) -> Any:
    path = resolve_metadata_path(path)
    if path is None:
        return {}
    with gzip.open(path, 'rt', encoding='utf-8') as fh:
        return json.load(fh)


def parse_coccinelle_output(output: str) -> list[dict[str, str | int]]:
    """Parse spatch context-mode output: unified diffs of the starred lines.

    Rules report by starring lines, so a match is a diff whose removed
    lines are the starred ones; each removed line becomes one hit with
    its line number in the original file.
    """
    result: list[dict[str, str | int]] = []
    file = ''
    old_line = 0
    for line in output.splitlines():
        if line.startswith('--- '):
            file = line[4:]
        elif line.startswith('@@'):
            hunk = re.match(r'@@ -(\d+)', line)
            if hunk:
                old_line = int(hunk.group(1))
        elif line.startswith('-'):
            result.append({'file': file, 'line': old_line})
            old_line += 1
        elif not line.startswith('+'):
            # Context lines advance the original-file counter; '+++' and added
            # lines do not exist in the original and are skipped by the above.
            old_line += 1
    return result


# spatch reports a fired --timeout in four shapes, and which one you get depends
# on how the run was invoked and which build ran, not on what went wrong:
#
#   file list, -j 1   exit 2    "timeout (we abort): <files>" then
#                               "Fatal error: exception <mod>Common.Timeout"
#   directory arg     exit 0    "EXN: <mod>Common.Timeout in <file>", one per file,
#                               then "An error occurred when attempting to ..."
#   file list, -j > 1 exit 255  "[Parmap]: error at index ... got exception
#                               <mod>Common.Timeout on core N"
#   patched build     exit 124  same abort line, then
#   (zygote branch)             "spatch: engine timeout (Common.Timeout)"
#
# The exit code alone settles nothing on stock spatch -- OCaml gives any uncaught
# exception exit 2, and the directory shape does not fail at all -- so the stderr
# text is the verdict there; 124 is the one code that means timeout by contract.
# The module prefix is build-dependent (Coccinelle_modules.Common.Timeout on the
# OCaml 5 builds, bare Common.Timeout on older ones), hence the optional group.
_TIMEOUT_EXN = re.compile(r'\bCommon\.Timeout\b')
_TIMEOUT_EXN_FILE = re.compile(r'^EXN: (?:\S+\.)?Common\.Timeout in (.+)$', re.MULTILINE)
_TIMEOUT_ABORT = re.compile(r'^timeout \(we abort\): (.*)$', re.MULTILINE)


def parse_spatch_timeout(stderr: str, returncode: int = 0) -> list[str] | None:
    """Classify a spatch run: None when no --timeout fired, else the files blamed.

    The list is empty when spatch named no file -- the parmap and fatal-error
    lines carry only the exception. Callers must treat "empty" as "timed out,
    files unknown", never as "did not time out".
    """
    if not _TIMEOUT_EXN.search(stderr) and returncode != 124:
        return None
    files = _TIMEOUT_EXN_FILE.findall(stderr)
    if not files:
        # The abort line lists the whole work unit, space-separated: under a file
        # list that is every file spatch was given, since they are one unit.
        for group in _TIMEOUT_ABORT.findall(stderr):
            files.extend(group.split())
    return sorted(set(files))


# The directory shape above is not peculiar to timeouts. Handed a directory,
# spatch catches *any* exception raised while it works on one file, prints
# `EXN: <exn> in <file>` (an ungated eprintf, so it survives --very-quiet), drops
# the file, and at the end prints the trailer and still exits 0 -- the file it
# never matched against reads exactly like a file with nothing to report. The
# trailer is printed only when such a catch fired (patching_failed starts false
# and nothing else sets it), so it alone already means "incomplete". The cause
# seen in practice is a torn AST-cache entry, which coccinelle neither re-parses
# nor evicts: `EXN: Failure("input_value: truncated object") in <file>` on every
# scan sharing the cache until the source changes.
_EXN_LINE = re.compile(r'^EXN: (?P<exn>.+) in (?P<file>.+)$', re.MULTILINE)
_TRUNCATED_TRAILER = 'An error occurred when attempting to transform some files.'


def parse_spatch_truncation(stderr: str) -> list[tuple[str, str]] | None:
    """Classify a spatch run: None when it scanned everything it was given, else
    the (exception, file) pairs it dropped.

    Timeout lines are excluded -- they are parse_spatch_timeout's, which callers
    consult first. The list is empty when spatch printed the trailer without
    naming a file (its workers' stderr was lost, say); callers must treat
    "empty" as "incomplete, files unknown", never as "complete". The exception
    is matched greedily so its own text may say " in ": the file is what follows
    the last one.
    """
    pairs = [(m['exn'], m['file']) for m in _EXN_LINE.finditer(stderr)]
    dropped = [(exn, file) for exn, file in pairs if not _TIMEOUT_EXN.search(exn)]
    if dropped:
        return dropped
    if _TRUNCATED_TRAILER in stderr and not pairs:
        return []
    return None


# What reading (or writing) an AST-cache entry raises when the entry is the
# problem rather than the source, as spatch 1.3.2 reports it: an empty entry
# (End_of_file), a short one (input_value: truncated object), garbage
# (input_value: bad object), and one that is missing, unreadable or a directory
# while its dependency record is not, or a full disk on write (Sys_error). A
# scan without --cache-prefix parses the source afresh and answers. Out_of_memory
# is deliberately absent: a fresh exec under the same cap would only repeat it.
# So is Invalid_argument: no bad entry raises it, and a parse that raises it
# would fail the rerun too.
_CACHE_FAULT = re.compile(r'input_value|End_of_file|Sys_error')


# Builds advertising 'summary' end every scan with one line saying what it did,
# and name every file they lost (fork commit "summary: every scan ends with
# SPATCH-SUMMARY"); unlike the EXN line, a SPATCH-DROP also covers a file that
# could not be read, which spatch otherwise skips without a word under
# --very-quiet.
_SUMMARY_LINE = re.compile(r'^SPATCH-SUMMARY (.*)$', re.MULTILINE)
_DROP_LINE = re.compile(
    r'^SPATCH-DROP kind=(?P<kind>\w+) reason="(?P<reason>(?:[^"\\]|\\.)*)" file=(?P<file>.*)$',
    re.MULTILINE,
)


def parse_spatch_summary(stderr: str) -> dict[str, int] | None:
    """The run's SPATCH-SUMMARY as counts, or None when there is not exactly one.

    On a build that prints it, None means the run did not finish the way a scan
    finishes -- never "nothing to report".
    """
    lines = _SUMMARY_LINE.findall(stderr)
    if len(lines) != 1:
        return None
    counts = {}
    for pair in lines[0].split():
        key, _, value = pair.partition('=')
        if value.isdigit():
            counts[key] = int(value)
    return counts


def parse_spatch_drops(stderr: str) -> list[tuple[str, str]]:
    """The (cause, file) pairs a run's SPATCH-DROP lines name, timeouts excluded."""
    drops = []
    for m in _DROP_LINE.finditer(stderr):
        if m['kind'] == 'timeout':
            continue
        reason = m['reason'].replace('\\"', '"').replace('\\\\', '\\')
        cause = reason if m['kind'] == 'exn' else f'{m["kind"]} ({reason})'
        drops.append((cause, m['file']))
    return drops


def is_cache_fault(dropped: list[tuple[str, str]]) -> bool:
    """Whether any dropped file was lost to the AST cache rather than to the parse."""
    return any(_CACHE_FAULT.search(exn) for exn, _file in dropped)


def parse_config(file: str) -> dict[str, Any]:
    parser = ConfigParser()
    with open(file) as fh:
        parser.read_string('[cvehound]\n' + fh.read())
    config: dict[str, Any] = dict(parser['cvehound'])

    for key in ['cve', 'exclude', 'files', 'ignore_files']:
        if key not in config:
            continue
        config[key] = config[key].split()

    if 'verbose' in config:
        try:
            config['verbose'] = int(config['verbose'])
        except ValueError:
            raise Exception('"verbose" should be an integer') from None

    for key in ['check_strict', 'all_files', 'exploit', 'cache_clear']:
        if key not in config:
            continue
        if config[key].lower() in ['y', 't', '1', 'yes', 'true']:
            config[key] = True
        elif config[key].lower() in ['n', 'f', '0', 'no', 'false']:
            config[key] = False
        else:
            raise Exception("Can't parse boolean argument " + key)

    return config
