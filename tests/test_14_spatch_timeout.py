#!/usr/bin/env python3

"""Pin the timeout classifier to what spatch actually prints.

parse_spatch_timeout() reads stderr because the exit code cannot answer the
question: handed a directory, spatch catches a fired --timeout per file, drops
that file's findings and still exits 0. That makes the marker text load-bearing,
and the marker text is not stable across builds -- the module prefix on the
exception depends on how coccinelle was compiled. The unit tests cover the
spellings seen so far; the live ones re-derive the marker from whichever spatch
is installed, so a coccinelle that renames it fails here instead of quietly
classifying every timeout as "nothing to see".
"""

import glob
import logging
import os
import pickle
import subprocess

import pytest
from conftest import SPATCH_TRAILER, TORN_CACHE_STDERR, write_tree

import cvehound
from cvehound.exception import SpatchError, SpatchTimeout, SpatchTruncated
from cvehound.oracle import hound_at
from cvehound.util import parse_spatch_timeout, parse_spatch_truncation

# Captured verbatim from spatch 1.3.2 under --very-quiet. One shape per way
# cvehound can invoke it; see the comment above parse_spatch_timeout().
# Builds without OCaml's wrapped modules spell the exception without the prefix.
FILE_LIST_STDERR = (
    'timeout (we abort): /k/drivers/a.c /k/drivers/b.c\nFatal error: exception {}Common.Timeout\n'
)
DIRECTORY_STDERR = (
    'EXN: Coccinelle_modules.Common.Timeout in /k/drivers/a.c\n'
    'EXN: Coccinelle_modules.Common.Timeout in /k/drivers/b.c\n'
    'An error occurred when attempting to transform some files.\n'
)
PARMAP_STDERR = (
    '[Parmap]: error at index j=0 in (0,0), chunksize=1 of a total of 1 got '
    'exception Coccinelle_modules.Common.Timeout on core 0 \n\n'
    'Aborting computation due to exception(s) raised in the workers\n'
)


@pytest.mark.parametrize('prefix', ['Coccinelle_modules.', ''], ids=['wrapped', 'bare'])
def test_file_list_shape_names_every_file(prefix):
    stderr = FILE_LIST_STDERR.format(prefix)
    assert parse_spatch_timeout(stderr) == ['/k/drivers/a.c', '/k/drivers/b.c']


def test_directory_shape_names_the_files_it_gave_up_on():
    assert parse_spatch_timeout(DIRECTORY_STDERR) == ['/k/drivers/a.c', '/k/drivers/b.c']


def test_parmap_shape_is_a_timeout_with_no_file():
    # Empty means "timed out, files unknown" -- callers must not read it as None.
    assert parse_spatch_timeout(PARMAP_STDERR) == []


@pytest.mark.parametrize(
    'stderr',
    [
        '',
        'init_defs_builtins: /usr/share/coccinelle/standard.h\n',
        # A different fatal exception is a SpatchError, not a timeout.
        'Fatal error: exception Coccinelle_modules.Common.UnixExit(2)\n',
        'EXN: Failure("bad") in /k/a.c\n',
    ],
)
def test_benign_stderr_is_not_a_timeout(stderr):
    assert parse_spatch_timeout(stderr) is None


def test_timeout_survives_the_pool_boundary():
    # Raised inside a ProcessPoolExecutor worker, so the extra state has to
    # round-trip; the default reduce would replay __init__ with the message.
    err = SpatchTimeout('CVE-1', '/k', 2, FILE_LIST_STDERR, 60, ['/k/a.c'])
    back = pickle.loads(pickle.dumps(err))
    assert isinstance(back, SpatchError)
    assert (back.files, back.timeout, back.wall) == (['/k/a.c'], 60, False)
    assert str(back) == str(err)


def test_wall_and_engine_budgets_read_differently():
    engine = SpatchTimeout('CVE-1', '/k', 2, '', 60, ['/k/a.c'])
    wall = SpatchTimeout('CVE-1', '/k', -9, '', 3600, [], wall=True)
    assert '60 CPU-seconds on /k/a.c' in str(engine)
    assert '3600s of wall time' in str(wall)


# --- truncation: a file spatch gave up on for any reason but a timeout -------


@pytest.mark.parametrize(
    ('stderr', 'dropped'),
    [
        (
            TORN_CACHE_STDERR,
            [('Failure("input_value: truncated object")', '/k/net/mptcp/protocol.c')],
        ),
        (
            'EXN: Out_of_memory in /k/drivers/a.c\n' + SPATCH_TRAILER,
            [('Out_of_memory', '/k/drivers/a.c')],
        ),
        # The exception's own text may say " in "; the file follows the last one.
        (
            'EXN: Failure("error in parsing") in /k/a.c\n',
            [('Failure("error in parsing")', '/k/a.c')],
        ),
        # Empty means "incomplete, files unknown" -- callers must not read it as None.
        (SPATCH_TRAILER, []),
        # Timeouts are parse_spatch_timeout's, even beside a file dropped for another reason.
        (DIRECTORY_STDERR, None),
        (
            DIRECTORY_STDERR[: -len(SPATCH_TRAILER)]
            + 'EXN: End_of_file in /k/drivers/c.c\n'
            + SPATCH_TRAILER,
            [('End_of_file', '/k/drivers/c.c')],
        ),
        (FILE_LIST_STDERR.format(''), None),
        (PARMAP_STDERR, None),
        ('', None),
        ('init_defs_builtins: /usr/share/coccinelle/standard.h\n', None),
    ],
    ids=[
        'torn-cache',
        'out-of-memory',
        'in-inside-exn',
        'trailer-only',
        'timeouts',
        'timeouts-and-a-drop',
        'file-list-timeout',
        'parmap-timeout',
        'empty',
        'benign',
    ],
)
def test_a_dropped_file_is_a_truncation(stderr, dropped):
    assert parse_spatch_truncation(stderr) == dropped


def test_truncation_survives_the_pool_boundary():
    err = SpatchTruncated(
        'CVE-1', '/k', 0, '', [('End_of_file', 'a.c'), ('End_of_file', 'b.c')], True
    )
    back = pickle.loads(pickle.dumps(err))
    assert isinstance(back, SpatchError)
    assert (back.dropped, back.retried) == (err.dropped, True)
    assert 'dropped 2 files (a.c, b.c) mid-scan in /k: End_of_file after one retry' in str(back)
    assert 'files it did not name' in str(SpatchTruncated('CVE-1', '/k', 0, SPATCH_TRAILER, []))


# --- _run_spatch hands back only a scan that finished ------------------------

SUMMARY = frozenset({'summary'})
CLEAN = 'SPATCH-SUMMARY groups=2 handled=1 skipped=1 dropped=0 timeouts=0 unreadable=0\n'
LOST = (
    'SPATCH-DROP kind=unreadable reason="prefilter" file=/k/b.c\n'
    'SPATCH-DROP kind=exn reason="Failure(\\"input_value: truncated object\\")" file=/k/a.c\n'
    'SPATCH-SUMMARY groups=2 handled=0 skipped=0 dropped=2 timeouts=0 unreadable=1\n'
)


@pytest.mark.parametrize(
    ('returncode', 'stderr', 'features', 'raised', 'files'),
    [
        (0, 'init_defs_builtins: /usr/share/coccinelle/standard.h\n', frozenset(), None, None),
        (0, TORN_CACHE_STDERR, frozenset(), SpatchTruncated, ['net/mptcp/protocol.c']),
        (0, SPATCH_TRAILER, frozenset(), SpatchTruncated, []),
        (0, DIRECTORY_STDERR, frozenset(), SpatchTimeout, ['drivers/a.c', 'drivers/b.c']),
        # A non-zero exit is the engine's own failure whatever it printed first.
        (2, TORN_CACHE_STDERR, frozenset(), SpatchError, None),
        # A build that ends every scan with a summary must say it finished, once.
        (0, CLEAN, SUMMARY, None, None),
        (0, '', SUMMARY, SpatchTruncated, []),
        (0, CLEAN + CLEAN, SUMMARY, SpatchTruncated, []),
        (0, LOST, SUMMARY, SpatchTruncated, ['a.c', 'b.c']),
    ],
    ids=[
        'complete',
        'torn-cache',
        'trailer-only',
        'timeout-wins',
        'nonzero-is-an-error',
        'summary',
        'no-summary',
        'two-summaries',
        'summary-counts-drops',
    ],
)
def test_run_spatch_returns_only_a_complete_scan(
    monkeypatch, returncode, stderr, features, raised, files
):
    monkeypatch.setattr(
        cvehound, '_exec_spatch', lambda cmd, env, wall: (returncode, 'hits', stderr)
    )

    def run():
        return cvehound._run_spatch('CVE-1', '/k', ['spatch'], 60, '/tmp', features=features)

    if raised is None:
        assert run() == 'hits'
        return
    with pytest.raises(raised) as excinfo:
        run()
    assert type(excinfo.value) is raised
    if files is not None:
        assert excinfo.value.files == files


# --- live: whatever spatch is installed still prints what we match on --------

CVE = 'CVE-0000-0000'
RULE = """\
/// Files: burn.c

@err@
identifier f, t;
@@

  f(...)
  {
  ...
* free_thing(t);
  ...
  use(t);
  ...
  }
"""


@pytest.fixture(scope='module')
def slow_tree(tmp_path_factory):
    """A one-file tree whose matching costs far more than one CPU-second.

    --timeout takes whole seconds and 0 disables it, so 1 is the tightest budget
    there is; the file has to overrun it by enough that a much faster machine
    still trips. It costs ~9 CPU-seconds here, and the run aborts the moment the
    budget goes, so the test pays about a second either way.
    """
    root = tmp_path_factory.mktemp('slow-tree')
    body = '\n'.join(
        f'\tstruct thing *t{i} = lookup(n + {i});\n'
        f'\tif (t{i}) {{ use(t{i}); free_thing(t{i}); }}\n'
        f'\tfor (i = 0; i < {i} + 4; i++) {{ acc += probe(i, t{i}); }}'
        for i in range(400)
    )
    (root / 'burn.c').write_text(
        'struct thing { int v; };\n'
        + '\n'.join(
            f'static void burn_{k}(int n)\n{{\n\tint i, acc = 0;\n{body}\n\tsink(acc);\n}}\n'
            for k in range(8)
        )
    )
    rule = root / f'{CVE}.cocci'
    rule.write_text(RULE)
    return root


def hound_with_rule(hound, tree, cve, rule):
    """A CVEhound pointed at tree, with rule registered under cve.

    hound_at only retargets .kernel; cve_all_rules and rules_metadata are shared
    with the session-wide instance, so both are replaced rather than mutated.
    """
    at = hound_at(hound, str(tree))
    at.cve_all_rules = {**hound.cve_all_rules, cve: str(rule)}
    at.rules_metadata = {}
    return at


@pytest.fixture
def slow_hound(hound, slow_tree):
    """A CVEhound pointed at that tree, with the rule registered under CVE."""
    return hound_with_rule(hound, slow_tree, CVE, slow_tree / f'{CVE}.cocci')


# The hinted-files shape depends on the build: stock spatch dies with the
# uncaught exception (exit 2); builds carrying the exit-124 patch (the zygote
# branch) report the coreutils-style timeout code instead. A directory scan
# exits 0.
@pytest.mark.parametrize(
    ('all_files', 'returncodes'),
    [(False, {2, 124}), (True, {0})],
    ids=['hinted-files', 'all-files'],
)
def test_check_cve_raises_spatch_timeout(slow_hound, monkeypatch, all_files, returncodes):
    """Both invocation shapes, through the code the CLI runs.

    This is also what pins the marker to whatever spatch is installed: err.files
    can only be right if parse_spatch_timeout matched what that build printed.
    The returncode is the reason the classifier reads stderr at all -- handed a
    directory spatch gives up on the file and still exits 0.
    """
    monkeypatch.setattr(cvehound, 'SPATCH_TIMEOUT', 1)
    with pytest.raises(SpatchTimeout) as excinfo:
        slow_hound.check_cve(CVE, all_files)
    err = excinfo.value
    assert err.files == ['burn.c']
    assert err.returncode in returncodes
    assert err.timeout == 1
    assert not err.wall


def test_wall_watchdog_reports_a_wall_timeout(slow_hound, monkeypatch):
    # The engine budget cannot see a process that is not burning CPU, which is
    # the whole reason for the outer one. It names no file: only spatch knows
    # where it got to, and it was killed before it could say.
    monkeypatch.setattr(cvehound, 'SPATCH_TIMEOUT', 0)
    monkeypatch.setattr(cvehound, 'SPATCH_WALL_TIMEOUT', 1)
    with pytest.raises(SpatchTimeout) as excinfo:
        slow_hound.check_cve(CVE)
    assert excinfo.value.wall
    assert excinfo.value.timeout == 1
    assert excinfo.value.files == []


def test_wall_watchdog_leaves_no_parmap_children(slow_hound, slow_tree, tmp_path, monkeypatch):
    """The reason the watchdog signals a process group and not a process.

    Under -j>1 spatch hands the work to parmap, which forks; killing the parent
    alone would orphan those children still burning cores. jobs=2 is what makes
    this test differ from the one above -- at jobs=1 there is nothing to orphan.

    chdir is belt and braces: check_cve() points --tmp-dir at a private
    mkdtemp it removes itself, so the scratch directory the SIGKILL strands
    lands nowhere near the repo root even without it.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cvehound, 'SPATCH_TIMEOUT', 0)
    monkeypatch.setattr(cvehound, 'SPATCH_WALL_TIMEOUT', 2)
    with pytest.raises(SpatchTimeout):
        slow_hound.check_cve(CVE, True, jobs=2)
    # pgrep matches the rule path, which is unique to this tree, so a surviving
    # child cannot be confused with another worker's spatch under xdist.
    survivors = subprocess.run(
        ['pgrep', '-fa', str(slow_tree / f'{CVE}.cocci')], capture_output=True, text=True
    )
    assert survivors.stdout == '', survivors.stdout


# --- live: a torn AST-cache entry is healed, not read as silence -------------

UAF_CVE = 'CVE-0000-0001'
UAF_RULE = """\
/// Files: a.c

@r@
expression t;
@@

* free_thing(t);
  ...
  use(t);
"""


@pytest.fixture
def torn_hound(hound, tmp_path):
    """A one-file tree the rule fires on, scanned with a private AST cache."""
    tree = tmp_path / 'tree'
    write_tree(
        tree,
        {
            'a.c': 'struct thing { int v; };\nvoid f(struct thing *t)\n{\n\tfree_thing(t);\n\tuse(t);\n}\n'
        },
    )
    rule = tmp_path / f'{UAF_CVE}.cocci'
    rule.write_text(UAF_RULE)
    at = hound_with_rule(hound, tree, UAF_CVE, rule)
    at.astcache = str(tmp_path / 'ast')
    return at


def tear(astcache: str) -> str:
    """Cut the one cached parse to 100 bytes, as a killed writer or a full disk would."""
    (entry,) = glob.glob(os.path.join(astcache, '**', 'a.c.ast_raw'), recursive=True)
    os.truncate(entry, 100)
    return entry


@pytest.mark.parametrize('jobs', [1, 2])
def test_a_torn_cache_entry_is_healed_not_read_as_silence(torn_hound, caplog, jobs):
    """A torn AST-cache entry, end to end.

    Before: `EXN: Failure("input_value: truncated object") in a.c`, exit 0, no
    findings -- "not vulnerable" for a file never scanned, on every scan sharing
    the cache. jobs=2 pins that parmap replays its workers' stderr, where the EXN
    line is printed, before the parent's trailer.
    """
    assert torn_hound.check_cve(UAF_CVE, True, jobs=jobs)
    entry = tear(torn_hound.astcache)
    with caplog.at_level(logging.WARNING, logger='cvehound.spatch'):
        assert torn_hound.check_cve(UAF_CVE, True, jobs=jobs)
    if 'cache-selfheal' in torn_hound.features:
        # The engine re-parses and rewrites the entry itself.
        assert os.path.getsize(entry) > 100, 'a self-healing build must rewrite the entry'
    else:
        assert 'dropped a.c mid-scan' in caplog.text and 'input_value' in caplog.text
        assert 'without the AST cache' in caplog.text
        assert not os.path.exists(entry), 'the torn entry must be evicted, or every scan pays again'
