#!/usr/bin/env python3

import contextlib
import functools
import os
import shutil
import tempfile
import textwrap
import time
from subprocess import CalledProcessError, run
from urllib.request import urlretrieve

import psutil
import pytest
from filelock import FileLock
from git import Repo
from git.exc import GitCommandError

from cvehound import CVEhound, _spatch_env, get_rule_cves
from cvehound.content import DEFAULT_BASE, METADATA_NAME
from cvehound.kbuild import KbuildParser
from cvehound.oracle import (
    BlobMaterializer,
    ResultCache,
    cached_all_files_check,
    cached_check,
    hound_at,
    object_header,
)
from cvehound.scripts.update_metadata import get_cache_dir
from cvehound.util import resolve_metadata_path

INITIAL_COMMIT = 'v2.6.12-rc2'
INITIAL_COMMIT_HASH = '1da177e4c3f41524e886b7f1b8a0c1fc7321cac2'
INITIAL_COMMITS = {INITIAL_COMMIT, INITIAL_COMMIT_HASH}
FETCH_INTERVAL = 6 * 3600

# Branches every test that takes the `branch` fixture runs against, unless
# --branch narrows them. Also the canonical set test_08 validates
# missing_backports against, so a --branch run cannot trip that lint.
DEFAULT_BRANCHES = (
    'origin/master',
    'next/master',
    'stable/linux-6.18.y',
    'stable/linux-6.12.y',
    'stable/linux-6.6.y',
    'stable/linux-6.1.y',
    'stable/linux-5.15.y',
    'stable/linux-5.10.y',
)

# (cve, branch) pairs whose upstream fix never reached that stable branch, so the
# rule legitimately fires there. The xfail is strict: once the backport lands the
# test XPASSes and the suite fails, which is the signal to delete the pair.
missing_backports = [
    ('CVE-2022-0998', 'stable/linux-5.15.y'),
    ('CVE-2023-4133', 'stable/linux-5.10.y'),
    ('CVE-2023-4133', 'stable/linux-5.15.y'),
    ('CVE-2023-4133', 'stable/linux-6.1.y'),
    ('CVE-2023-23005', 'stable/linux-6.1.y'),
    ('CVE-2024-26595', 'stable/linux-5.10.y'),
    ('CVE-2024-26595', 'stable/linux-5.15.y'),
    ('CVE-2024-26799', 'stable/linux-6.1.y'),
]


def pytest_addoption(parser):
    parser.addoption(
        '--cve',
        action='append',
        default=[],
        help='list of CVEs',
    )
    parser.addoption(
        '--branch',
        action='append',
        default=[],
        help='list of linux-stable branches to run tests on',
    )
    parser.addoption('--runslow', action='store_true', default=False, help='run slow tests')
    parser.addoption(
        '--runmetadata',
        action='store_true',
        default=False,
        help='run tests that check kernel_cves.json against the kernel git tree',
    )
    parser.addoption(
        '--dir',
        action='store',
        default=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'linux'),
        help='linux kernel sources dir',
    )
    parser.addoption(
        '--between-mode',
        action='store',
        default='tags',
        choices=('tags', 'commits'),
        help='test_05 verification points: tags incl. -rc (default) or every commit',
    )
    parser.addoption(
        '--no-result-cache',
        action='store_true',
        default=False,
        help='run every spatch check even when a cached verdict exists',
    )


linux_repo = None
_cvehound = None
_kernel_checkout = None
_materializer = None
_shared_root = None
_result_cache = None
_fresh_worktrees = set()
branches = []
cves = []


def _is_worker(config):
    return hasattr(config, 'workerinput')


def use_worktrees():
    env = os.environ.get('CVEHOUND_TEST_WORKTREES')
    if env is not None:
        return env != '0'
    return os.environ.get('GITHUB_ACTIONS') != 'true'


class KernelCheckout:
    def __init__(self, repo):
        self.repo = repo
        self.current = None

    def checkout(self, commit):
        if self.current == commit:
            return

        self.current = None
        self.repo.git.checkout('--force', commit)
        self.current = commit


def _tune_repo(repo):
    """Apply idempotent git performance settings to the kernel repo.

    checkout.workers=0 parallelizes working-tree updates across all cores and
    feature.manyFiles enables index v4 plus the untracked cache. The one-time
    Bloom-filter commit-graph (--changed-paths) accelerates the path-limited
    `git log` queries in test_05 and the topo-order ranking at collection time;
    fetch.writeCommitGraph keeps it current (new layers inherit the filters).
    """
    for key, value in (
        ('checkout.workers', '0'),
        ('feature.manyFiles', 'true'),
        ('fetch.writeCommitGraph', 'true'),
    ):
        repo.git.config(key, value)
    try:
        done = repo.git.config('--get', 'cvehound.commitgraphbloom')
    except GitCommandError:
        done = ''
    if done != '1':
        repo.git.commit_graph('write', '--reachable', '--changed-paths', '--split=replace')
        repo.git.config('cvehound.commitgraphbloom', '1')


def _reset_worktree(repo):
    # A clean tree needs no reset/clean/checkout: tests force-checkout the
    # commits they need and never rely on where HEAD currently points.
    # --ignored: build products (.config, *.o, include/generated/) are
    # invisible to plain --porcelain but must still trigger the `-x` clean,
    # or all_files scans grep stale artifacts forever.
    if not repo.git.status('--porcelain', '--ignored'):
        return
    repo.head.reset(index=True, working_tree=True)
    repo.git.clean('-f', '-x', '-d')
    repo.git.checkout('origin/master')


def _spatch_identity(hound):
    # The version line alone does not identify the binary: the bundled build
    # and a distro one report the same "spatch version 1.3.2 compiled with
    # OCaml ...", yet differ in patches and configure flags (--disable-python),
    # which changes verdicts. Keep the path and the whole banner, whose second
    # line lists those flags, so switching binaries starts a fresh namespace.
    out = run([hound.spatch, '--version'], capture_output=True, check=True, text=True)
    # The transport is part of the identity, taken from what the instance
    # actually resolved rather than from the environment: these are settings
    # now, so with the zygote defaulting to on there is no env var left to
    # scan, and a verdict computed under one transport must not be replayed
    # under another.
    return '\x00'.join(
        (
            hound.spatch,
            out.stdout.strip(),
            f'zygote={hound.zygote}',
            f'astcache={bool(hound.astcache)}',
        )
    )


def _fetch_remotes(repo):
    if os.environ.get('CVEHOUND_TEST_OFFLINE'):
        return
    fetch_head = os.path.join(repo.git_dir, 'FETCH_HEAD')
    if os.path.isfile(fetch_head) and time.time() - os.path.getmtime(fetch_head) < FETCH_INTERVAL:
        return
    try:
        repo.remotes.origin.fetch()
        repo.remotes.stable.fetch()
        repo.remotes.next.fetch()
    except Exception:
        pass


def _ensure_metadata():
    """Point CVEHOUND_METADATA at a usable blob when the checkout has none.

    The metadata blob is not git-tracked (CI publishes it as a content-latest
    release asset); fetch it once into the cvehound cache dir.
    """
    if os.environ.get('CVEHOUND_METADATA'):
        return
    # CVEHOUND_CONTENT=none is already set, so this resolves to the packaged
    # blob or None -- exactly "does the checkout have a blob".
    if resolve_metadata_path(None):
        return
    blob_name = os.path.basename(METADATA_NAME)
    cache = get_cache_dir()
    dest = os.path.join(cache, blob_name)
    if not os.path.isfile(dest):
        os.makedirs(cache, exist_ok=True)
        # Download to a temp name first: an interrupted download must not
        # leave a truncated blob that poisons every later run.
        tmp = dest + '.download'
        urlretrieve(DEFAULT_BASE + '/' + blob_name, tmp)
        os.replace(tmp, dest)
    os.environ['CVEHOUND_METADATA'] = dest


def _raise_priority():
    """Ask for as much CPU and I/O priority as we are allowed, one ask at a time.

    Each ask is independently privileged, so each gets its own handler: sharing
    one try means the first refusal silently cancels every ask after it, and on
    a box without CAP_SYS_NICE (CI grants it with setcap; a developer machine
    does not) the first refusal is the very first call.

    Nothing here is required -- the suite runs at whatever priority it is given.
    """
    proc = psutil.Process()
    # -20 is the floor Linux accepts; anything lower is an error, not a stronger
    # request. Needs CAP_SYS_NICE or a raised RLIMIT_NICE.
    with contextlib.suppress(Exception):
        proc.nice(-20)
    # Real-time I/O needs CAP_SYS_ADMIN; best-effort 0 needs nothing. First one
    # that takes, wins. The classes are looked up by name *inside* the suppress
    # because psutil defines them only where it implements ionice: naming them
    # in the loop header evaluates them before any handler is installed, so on
    # a platform without ionice the lookup -- not the ask -- is what fails, and
    # it fails all the way out through pytest_configure.
    for ioclass in ('IOPRIO_CLASS_RT', 'IOPRIO_CLASS_BE'):
        with contextlib.suppress(Exception):
            proc.ionice(getattr(psutil, ioclass), value=0)
            break


def pytest_configure(config):
    global linux_repo
    global _cvehound
    global _kernel_checkout
    global _materializer
    global _shared_root
    global _result_cache
    global branches
    global cves

    # The suite must parametrize over the repository's own rules and metadata,
    # never over a developer's content overlay.
    os.environ['CVEHOUND_CONTENT'] = 'none'
    _ensure_metadata()

    _raise_priority()

    cves = config.getoption('cve')
    if not cves:
        (cves, _, _) = get_rule_cves()
        cves = cves.keys()

    if _is_worker(config):
        # Repo prep already happened on the xdist controller; reuse its state.
        linux_repo = Repo(config.getoption('dir'))
        _shared_root = config.workerinput['cvehound_root']
    else:
        linux = config.getoption('dir')
        repo = None
        if os.path.isdir(os.path.join(linux, '.git')):
            repo = Repo(linux)
            _tune_repo(repo)
            _reset_worktree(repo)
            _fetch_remotes(repo)
        else:
            cwd = os.getcwd()
            os.makedirs(linux, exist_ok=True)
            os.chdir(linux)
            repo = Repo.clone_from(
                'git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git', '.'
            )
            repo.create_remote(
                'stable', 'git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git'
            )
            repo.create_remote(
                'next', 'git://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git'
            )
            repo.remotes.stable.fetch()
            repo.remotes.next.fetch()
            os.chdir(cwd)
            _tune_repo(repo)

        linux_repo = repo
        _shared_root = tempfile.mkdtemp(prefix='cvehound-tests-')

    # The suite must never write into the user's real AST cache. Its mini-trees
    # live under a fresh mkdtemp per session, so cache entries -- whose names
    # embed the absolute source path -- could never be reused anyway: the hit
    # rate is structurally zero while the writes are real, which is a few
    # hundred MB of garbage per run. Opt out unless a run asks for it.
    os.environ.setdefault('CVEHOUND_SPATCH_ASTCACHE', 'none')

    _cvehound = CVEhound(linux_repo.working_tree_dir)
    _kernel_checkout = KernelCheckout(linux_repo)
    _materializer = BlobMaterializer(linux_repo.git, os.path.join(_shared_root, 'store'))
    if not config.getoption('--no-result-cache'):
        _result_cache = ResultCache(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), '.result_cache'),
            _spatch_identity(_cvehound),
            worker=os.environ.get('PYTEST_XDIST_WORKER', 'main'),
        )

    branches = config.getoption('branch') or list(DEFAULT_BRANCHES)


def pytest_unconfigure(config):
    if _is_worker(config):
        return
    if _result_cache:
        if _result_cache.hits or _result_cache.misses:
            print(f'\nresult cache: {_result_cache.hits} hits, {_result_cache.misses} misses')
        _result_cache.compact()
    if _shared_root:
        shutil.rmtree(_shared_root, ignore_errors=True)


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node):
    # xdist controller hook: hand each worker the shared blob store so the
    # per-session trees are materialized once, not per worker.
    node.workerinput['cvehound_root'] = _shared_root


def pytest_sessionfinish(session, exitstatus):
    if _result_cache and _is_worker(session.config):
        session.config.workeroutput['cvehound_cache'] = [
            _result_cache.hits,
            _result_cache.misses,
        ]


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node, error):
    stats = getattr(node, 'workeroutput', {}).get('cvehound_cache')
    if stats and _result_cache:
        _result_cache.hits += stats[0]
        _result_cache.misses += stats[1]


# spatch 1.3.2 on a torn AST-cache entry (cut to 100 bytes), shared by the
# classifier and transport tests. Handed a directory, it names the file it
# dropped and still exits 0; handed the file by name, it exits 255 and names no
# file.
SPATCH_TRAILER = 'An error occurred when attempting to transform some files.\n'
TORN_CACHE_STDERR = (
    'EXN: Failure("input_value: truncated object") in /k/net/mptcp/protocol.c\n' + SPATCH_TRAILER
)
NAMED_TORN_STDERR = 'exn while in timeout_function\ninput_value: truncated object\n'


def write_tree(root, files):
    """Materialize a synthetic kernel tree: {relative path: file content}."""
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content))


def build_map(root, arch='x86'):
    """Build the Kbuild config map of a tree, keyed by relative path."""
    kernel = os.path.abspath(str(root))
    config = KbuildParser(None, arch, kernel).parse_tree()
    return {os.path.relpath(k, kernel): v for k, v in config.items()}


@pytest.fixture
def repo():
    return linux_repo


@pytest.fixture
def hound():
    return _cvehound


@pytest.fixture
def kernel_checkout():
    return _kernel_checkout


@pytest.fixture
def materializer():
    return _materializer


@pytest.fixture
def between_mode(request):
    return request.config.getoption('--between-mode')


@pytest.fixture
def result_cache():
    return _result_cache


@pytest.fixture
def sig_check(materializer, hound, result_cache):
    """Factory: cached bool verdict for a rule on a blob signature."""

    def check(sig, cve):
        return cached_check(hound, materializer, result_cache, sig, cve)

    return check


@pytest.fixture
def tree_check(materializer, hound, sig_check):
    """Factory: cached bool verdict for a rule at a commit, without checkouts."""

    def check(commit, cve):
        return sig_check(materializer.sig(commit, hound.get_rule_files(cve)), cve)

    return check


@functools.cache
def _branch_commit_oid(branch_name):
    """The branch head's commit oid.

    Through the persistent cat-file stream, not repo.rev_parse: that walks all
    ~6k packed refs per call (~8.5ms against ~9us), and this runs inside the
    worktree lock where every worker queues behind it.
    """
    obj = object_header(linux_repo.git, f'{branch_name}^{{commit}}')
    if obj is None:
        raise ValueError(f'unresolvable branch: {branch_name}')
    return obj[0]


def _worktree_is_at(path, branch_name):
    """True when the worktree already sits on the branch head.

    The freshness fact belongs to the worktree, not to whoever last looked:
    _fresh_worktrees is per-process, and with the full-tree tests no longer
    pinned one branch per worker every worker visits every worktree. Asking
    HEAD is derived from the state itself, so it stays right no matter which
    process (or hand) moved the tree last.
    """
    try:
        head = run(
            ['git', '-C', path, 'rev-parse', 'HEAD'], capture_output=True, check=True, text=True
        ).stdout.strip()
    except CalledProcessError:
        return False
    return head == _branch_commit_oid(branch_name)


def _branch_worktree(branch_name):
    """A persistent detached worktree at the branch head.

    Worktrees survive the session (a full kernel checkout costs ~5-15s per
    branch, and /tmp clears on reboot anyway); each session refreshes a reused
    worktree to the current branch head once. The lock covers creation and
    refresh against concurrent pytest sessions.
    """
    root = os.path.join(tempfile.gettempdir(), f'cvehound-worktrees-{os.getuid()}')
    os.makedirs(root, exist_ok=True)
    path = os.path.join(root, branch_name.replace('/', '-'))
    if path in _fresh_worktrees:
        return path
    with FileLock(path + '.lock'):
        if not os.path.isdir(path):
            try:
                linux_repo.git.worktree('add', '--detach', '--force', path, branch_name)
            except GitCommandError:
                # A stale admin entry (e.g. after a /tmp wipe) blocks the add:
                # prune and retry. Pruning only on this failure path keeps it
                # away from sibling workers' in-flight worktree adds.
                linux_repo.git.worktree('prune')
                linux_repo.git.worktree('add', '--detach', '--force', path, branch_name)
        elif not _worktree_is_at(path, branch_name):
            run(
                ['git', '-C', path, 'checkout', '--force', '--detach', branch_name],
                capture_output=True,
                check=True,
            )
    _fresh_worktrees.add(path)
    return path


@pytest.fixture
def branch_hound(hound, kernel_checkout):
    """Factory: a CVEhound over a full tree at a branch head.

    A detached worktree per branch when enabled (the default outside CI),
    falling back to checkouts in the shared tree otherwise.
    """

    def make(branch_name):
        if not use_worktrees():
            kernel_checkout.checkout(branch_name)
            return _cvehound
        return hound_at(hound, _branch_worktree(branch_name))

    return make


@pytest.fixture
def branch_check(hound, branch_hound, materializer, result_cache, all_files_jobs):
    """Factory: cached bool verdict of an all_files scan at a branch head."""

    def check(branch_name, cve):
        return cached_all_files_check(
            hound,
            lambda: branch_hound(branch_name),
            result_cache,
            materializer.whole_tree_sig(branch_name),
            cve,
            all_files_jobs,
        )

    return check


@pytest.fixture
def all_files_jobs():
    """spatch -j for whole-tree scans: a scan alone on the box may take it all.

    Two cases, not a spectrum. Worktree mode fans the scans out across every
    worker, so each gets one core's worth; the shared-tree fallback funnels them
    into a single xdist group, where the one running scan may use every core.
    Stated rather than divided, so a cgroup-limited runner -- where xdist counts
    affinity and os.cpu_count() does not -- cannot land somewhere in between.
    """
    workers = int(os.environ.get('PYTEST_XDIST_WORKER_COUNT', '1'))
    if use_worktrees() and workers > 1:
        return 1
    return os.cpu_count() or 1


def pytest_generate_tests(metafunc):
    if 'branch' in metafunc.fixturenames:
        params = branches
        if metafunc.definition.get_closest_marker('kernel_history') and not use_worktrees():
            # Full-tree tests declare kernel_history('branch'), and grouping
            # them is about the tree they share, not the branch they name:
            # without worktrees every scan runs in one checkout, so they must
            # serialize into a single group and _reorder_kernel_tests keeps the
            # branch switches down. With worktrees the trees are separate
            # directories that need no coordination, and any grouping would
            # only cap the fan-out below the worker count. Marking at
            # parametrize time guarantees xdist's nodeid rewrite sees the
            # marker regardless of hook ordering.
            params = [
                pytest.param(branch, marks=pytest.mark.xdist_group('shared-tree'))
                for branch in branches
            ]
        metafunc.parametrize('branch', params)

    if 'cve' in metafunc.fixturenames:
        metafunc.parametrize('cve', cves)


def _get_kernel_route(item):
    marker = item.get_closest_marker('kernel_history')
    if marker is None:
        return ()
    if marker.args != ('branch',):
        # The richer fix/fixes/initial vocabulary died with the checkout-based
        # tests; only the branch route (test_06's shared-tree fallback) is left.
        raise pytest.UsageError(f'unknown kernel_history route {marker.args!r} on {item.nodeid}')
    return (item.callspec.params['branch'],)


def _reorder_kernel_tests(items):
    """Group full-tree tests by branch: the shared-tree fallback then switches
    its checkout once per branch instead of once per test, and worktree runs get
    the page-cache locality for free. Skipped items keep their slots and never
    influence the order."""
    records = []
    for index, item in enumerate(items):
        if item.get_closest_marker('skip') is not None:
            continue
        route = _get_kernel_route(item)
        if route:
            records.append((index, item, route))

    if len(records) < 2:
        return

    slots = [index for index, _, _ in records]
    ordered = sorted(records, key=lambda record: (record[2], record[0]))
    for slot, (_, item, _) in zip(slots, ordered, strict=True):
        items[slot] = item


def _deselect_non_cve_tests(config, items):
    """--cve means "test these rules": drop everything not parametrized by cve.

    Harness unit tests can't be affected by a rule, so they are noise in the
    rule-iteration loop. Explicitly given paths still win: `pytest --cve=X
    tests/test_12_kerneltree.py` runs what it names.
    """
    if not config.getoption('cve') or config.getoption('file_or_dir'):
        return
    keep = []
    deselected = []
    for item in items:
        callspec = getattr(item, 'callspec', None)
        if callspec is not None and 'cve' in callspec.params:
            keep.append(item)
        else:
            deselected.append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = keep


def pytest_collection_modifyitems(config, items):
    _deselect_non_cve_tests(config, items)
    runslow = config.getoption('--runslow')
    runmetadata = config.getoption('--runmetadata')
    skip_slow = pytest.mark.skip(reason='need --runslow option to run')
    skip_fast = pytest.mark.skip(reason='slow tests cover these testcases')
    skip_metadata = pytest.mark.skip(reason='need --runmetadata option to run')
    fail_notbackported = pytest.mark.xfail(
        strict=True,
        reason='CVE not backported yet; if it now is, drop the (cve, branch) pair '
        'from missing_backports in tests/conftest.py',
    )
    for item in items:
        if not runslow and 'slow' in item.keywords:
            item.add_marker(skip_slow)
        if runslow and 'fast' in item.keywords:
            item.add_marker(skip_fast)
        if not runmetadata and 'metadata' in item.keywords:
            item.add_marker(skip_metadata)
        if 'notbackported' in item.keywords:
            params = item.callspec.params
            mark = None
            for m in item.own_markers:
                if m.name == 'notbackported':
                    mark = m
                    break
            if (params['cve'], params['branch']) in mark.args[1]:
                item.add_marker(fail_notbackported)
        for name in ('ownfixes', 'nometadata'):
            if name not in item.keywords:
                continue
            params = item.callspec.params
            mark = None
            for m in item.own_markers:
                if m.name == name:
                    mark = m
                    break
            for rec in mark.args[1]:
                # A record is either a (cve, reason) pair or a bare CVE id, in
                # which case the reason is shared by the whole list
                if isinstance(rec, str):
                    rec = (rec, mark.kwargs.get('reason', name))
                if params['cve'] == rec[0]:
                    item.add_marker(pytest.mark.xfail(reason=rec[1]))

    _reorder_kernel_tests(items)


# --- synthetic repositories for the git modes ---------------------------------
#
# A kernel-shaped history small enough to build per test: the git modes are
# exercised against it without the real checkout, and a throwaway rule
# (registered with CVEhound.add_rule) gives spatch something to fire on.

VULNERABLE_C = """\
#include <linux/kconfig.h>

int foo(int *p)
{
\tvulnerable_call(p);
\treturn *p;
}
"""

FIXED_C = """\
#include <linux/kconfig.h>

int foo(int *p)
{
\tif (!p)
\t\treturn -1;
\treturn *p;
}
"""

MAKEFILE = 'VERSION = 6\nPATCHLEVEL = 1\nSUBLEVEL = 0\nEXTRAVERSION =\nNAME = Test\n'

# Stands in for the mainline fix a stable backport cites in its message.
UPSTREAM_FIX = '0123456789abcdef0123456789abcdef01234567'

TOY_RULE = """\
/// Files: drivers/foo/foo.c drivers/foo/bar.c
/// Fix: {fix}
/// Fixes: {fixes}

@@
expression E;
@@

* vulnerable_call(E);
"""


class MiniRepo:
    """A git repository built commit by commit from dicts of files."""

    def __init__(self, path):
        self.path = str(path)
        os.makedirs(self.path, exist_ok=True)
        self.env = dict(
            _spatch_env(),
            HOME=self.path,
            GIT_AUTHOR_NAME='Test',
            GIT_AUTHOR_EMAIL='test@example.com',
            GIT_COMMITTER_NAME='Test',
            GIT_COMMITTER_EMAIL='test@example.com',
            GIT_AUTHOR_DATE='2024-01-01T00:00:00Z',
            GIT_COMMITTER_DATE='2024-01-01T00:00:00Z',
        )
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'commit.gpgsign', 'false')
        self.commits = []

    def git(self, *args, input=None):
        proc = run(
            ['git', *args],
            cwd=self.path,
            env=self.env,
            input=input,
            capture_output=True,
            check=True,
        )
        return proc.stdout.decode()

    def commit(self, files, message):
        """Write (or, for a None value, remove) each file and commit; returns the sha."""
        for relpath, content in files.items():
            path = os.path.join(self.path, relpath)
            if content is None:
                os.unlink(path)
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as fh:
                fh.write(content)
        # Distinct timestamps keep --since bounds and describe ordering meaningful.
        stamp = f'2024-01-{len(self.commits) + 1:02d}T00:00:00Z'
        self.env['GIT_AUTHOR_DATE'] = self.env['GIT_COMMITTER_DATE'] = stamp
        self.git('add', '-A')
        self.git('commit', '-q', '-m', message)
        sha = self.git('rev-parse', 'HEAD').strip()
        self.commits.append(sha)
        return sha

    def tag(self, name):
        self.git('tag', name)


@pytest.fixture
def mini_repo(tmp_path):
    """Three commits: vulnerable (v6.1), fixed by a backport (v6.1.1), renamed."""
    repo = MiniRepo(tmp_path / 'repo')
    vuln = repo.commit(
        {
            'Makefile': MAKEFILE,
            'Kbuild': '',
            'include/linux/kconfig.h': '/* kconfig */\n',
            'arch/x86/Makefile': '',
            'drivers/foo/Makefile': 'obj-$(CONFIG_FOO) += foo.o\n',
            'drivers/foo/foo.c': VULNERABLE_C,
        },
        'Initial kernel',
    )
    repo.tag('v6.1')
    repo.commit(
        {'drivers/foo/foo.c': FIXED_C},
        f'foo: check the pointer\n\ncommit {UPSTREAM_FIX} upstream\n\nFixes: {vuln[:12]} ("Initial kernel")\n',
    )
    repo.tag('v6.1.1')
    repo.commit(
        {'drivers/foo/foo.c': None, 'drivers/foo/bar.c': FIXED_C},
        'foo: rename foo.c to bar.c',
    )
    return repo


@pytest.fixture
def toy_rule(tmp_path, mini_repo):
    """A rule file that fires on VULNERABLE_C and not on FIXED_C."""
    path = tmp_path / 'CVE-2099-0001.cocci'
    path.write_text(TOY_RULE.format(fix=mini_repo.commits[1], fixes=mini_repo.commits[0]))
    return str(path)
