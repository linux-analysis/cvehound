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

import pickle
import subprocess

import pytest

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


BENIGN_STDERR = [
    '',
    'init_defs_builtins: /usr/share/coccinelle/standard.h\n',
    # A different fatal exception is a SpatchError (non-zero exit), neither a
    # timeout nor a truncation.
    'Fatal error: exception Coccinelle_modules.Common.UnixExit(2)\n',
]


@pytest.mark.parametrize('stderr', BENIGN_STDERR)
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

TRAILER = 'An error occurred when attempting to transform some files.\n'
# Captured from the wheel's spatch over a directory whose AST-cache entry for the
# one file it had to parse was truncated to 100 bytes (exit 0, empty stdout).
TORN_CACHE_STDERR = (
    'EXN: Failure("input_value: truncated object") in /k/net/mptcp/protocol.c\n' + TRAILER
)
OOM_STDERR = 'EXN: Out_of_memory in /k/drivers/a.c\n' + TRAILER
MIXED_STDERR = DIRECTORY_STDERR[: -len(TRAILER)] + 'EXN: End_of_file in /k/drivers/c.c\n' + TRAILER


@pytest.mark.parametrize(
    ('stderr', 'expected'),
    [
        (
            TORN_CACHE_STDERR,
            [('Failure("input_value: truncated object")', '/k/net/mptcp/protocol.c')],
        ),
        (OOM_STDERR, [('Out_of_memory', '/k/drivers/a.c')]),
        # Formerly pinned here as benign: it is the shape of a file never scanned.
        ('EXN: Failure("bad") in /k/a.c\n', [('Failure("bad")', '/k/a.c')]),
        # The exception's own text may say " in "; the file follows the last one.
        (
            'EXN: Failure("error in parsing") in /k/a.c\n',
            [('Failure("error in parsing")', '/k/a.c')],
        ),
    ],
    ids=['torn-cache', 'out-of-memory', 'formerly-benign', 'in-inside-exn'],
)
def test_a_dropped_file_is_a_truncation_not_a_timeout(stderr, expected):
    assert parse_spatch_timeout(stderr) is None
    assert parse_spatch_truncation(stderr) == expected


def test_trailer_alone_is_truncated_files_unknown():
    # Empty means "incomplete, files unknown" -- callers must not read it as None.
    assert parse_spatch_truncation(TRAILER) == []


def test_the_timeout_directory_shape_is_not_a_truncation():
    # Same trailer, but every dropped file timed out: parse_spatch_timeout owns it.
    assert parse_spatch_truncation(DIRECTORY_STDERR) is None


def test_mixed_shape_reports_only_the_non_timeout_drops():
    assert parse_spatch_truncation(MIXED_STDERR) == [('End_of_file', '/k/drivers/c.c')]


@pytest.mark.parametrize('stderr', BENIGN_STDERR + [FILE_LIST_STDERR.format(''), PARMAP_STDERR])
def test_benign_and_timeout_stderr_is_not_a_truncation(stderr):
    assert parse_spatch_truncation(stderr) is None


def test_truncation_survives_the_pool_boundary():
    err = SpatchTruncated('CVE-1', '/k', 0, TORN_CACHE_STDERR, [('End_of_file', 'a.c')], True)
    back = pickle.loads(pickle.dumps(err))
    assert isinstance(back, SpatchError)
    assert (back.dropped, back.retried, back.files) == ([('End_of_file', 'a.c')], True, ['a.c'])
    assert str(back) == str(err)


def test_truncation_message_names_files_and_causes():
    named = SpatchTruncated('CVE-1', '/k', 0, '', [('End_of_file', 'a.c'), ('End_of_file', 'b.c')])
    unnamed = SpatchTruncated('CVE-1', '/k', 0, TRAILER, [], retried=True)
    assert 'dropped 2 files (a.c, b.c) mid-scan in /k: End_of_file' in str(named)
    assert 'files it did not name' in str(unnamed)
    assert 'after one retry' in str(unnamed)


@pytest.mark.parametrize(
    ('returncode', 'stderr', 'raised'),
    [
        (0, TORN_CACHE_STDERR, SpatchTruncated),
        (0, TRAILER, SpatchTruncated),
        (0, DIRECTORY_STDERR, SpatchTimeout),
        # A non-zero exit is the engine's own failure whatever it printed first.
        (2, TORN_CACHE_STDERR, SpatchError),
    ],
    ids=['torn-cache', 'trailer-only', 'timeout-wins', 'nonzero-is-an-error'],
)
def test_run_spatch_never_returns_an_incomplete_scan(monkeypatch, returncode, stderr, raised):
    """The transport-level contract: a dropped file raises, and only the kind it raises varies."""
    monkeypatch.setattr(cvehound, '_exec_spatch', lambda cmd, env, wall: (returncode, '', stderr))
    with pytest.raises(raised) as excinfo:
        cvehound._run_spatch('CVE-2022-50071', '/k', ['spatch'], 60, '/tmp')
    assert type(excinfo.value) is raised
    if raised is SpatchTruncated and excinfo.value.dropped:
        assert excinfo.value.files == ['net/mptcp/protocol.c']


def test_run_spatch_still_returns_a_complete_scan(monkeypatch):
    monkeypatch.setattr(
        cvehound, '_exec_spatch', lambda cmd, env, wall: (0, 'hits', BENIGN_STDERR[1])
    )
    assert cvehound._run_spatch('CVE-1', '/k', ['spatch'], 60, '/tmp') == 'hits'


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


@pytest.fixture
def slow_hound(hound, slow_tree):
    """A CVEhound pointed at that tree, with the rule registered under CVE.

    hound_at only retargets .kernel; cve_all_rules and rules_metadata are shared
    with the session-wide instance, so both are replaced rather than mutated.
    """
    at = hound_at(hound, str(slow_tree))
    at.cve_all_rules = {**hound.cve_all_rules, CVE: str(slow_tree / f'{CVE}.cocci')}
    at.rules_metadata = {}
    return at


# The hinted-files shape depends on the build: stock spatch dies with the
# uncaught exception (exit 2); builds carrying the exit-124 patch (the zygote
# branch) report the coreutils-style timeout code instead.
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
