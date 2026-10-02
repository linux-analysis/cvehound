#!/usr/bin/env python3

"""A transport fault, or a file the engine dropped, must not become the rule's verdict.

The fork server dies on some whole-tree scans (the child segfaults in OCaml's
unmarshaller); the identical scan run as a plain exec answers normally. Losing
the request would mark a valid rule not-strong for a reason that has nothing to
do with the rule, so an inferred zygote degrades to one spatch per rule. A
demanded one still fails loudly. A scan that dropped a file gets one rerun when
a rerun removes the cause -- a torn AST-cache entry, an inferred zygote's heap --
and is otherwise reported as truncated, never returned as clean.
"""

import pathlib

import pytest
from conftest import SPATCH_TRAILER, TORN_CACHE_STDERR

import cvehound
from cvehound import spatch_zygote
from cvehound.exception import SpatchError, SpatchTimeout, SpatchTruncated


@pytest.fixture
def transports(monkeypatch):
    """Record which transport ran; the zygote always dies."""
    calls = []

    def dead_zygote(cmd, env, workdir, wall_timeout, degrade=True):
        calls.append('zygote')
        raise spatch_zygote.ZygoteDied('server exited mid-request')

    def exec_spatch(cmd, env, wall_timeout):
        calls.append('exec')
        return 0, 'stdout from the fallback', ''

    monkeypatch.setattr(spatch_zygote, 'run', dead_zygote)
    monkeypatch.setattr(cvehound, '_exec_spatch', exec_spatch)
    return calls


def test_died_zygote_falls_back(transports):
    out = cvehound._run_spatch('CVE-2021-47314', '/kernel', ['spatch'], 60, '/tmp', zygote=True)
    assert out == 'stdout from the fallback'
    assert transports == ['zygote', 'exec']


def test_demanded_zygote_still_fails(transports):
    with pytest.raises(SpatchError):
        cvehound._run_spatch(
            'CVE-2021-47314', '/kernel', ['spatch'], 60, '/tmp', zygote=True, demanded=True
        )
    assert transports == ['zygote'], 'a demanded zygote must not degrade silently'


@pytest.mark.parametrize(
    'rc, what', [(-11, 'SIGSEGV in the forked child'), (2, 'uncaught OCaml exception')]
)
def test_failed_child_falls_back(monkeypatch, rc, what):
    """The server survives, so only the return status says the request failed."""
    calls = []

    def crashing_child(cmd, env, workdir, wall_timeout, degrade=True):
        calls.append('zygote')
        return rc, '', ''  # the server is fine; this request is not

    def exec_spatch(cmd, env, wall_timeout):
        calls.append('exec')
        return 0, 'stdout from the fallback', ''

    monkeypatch.setattr(spatch_zygote, 'run', crashing_child)
    monkeypatch.setattr(cvehound, '_exec_spatch', exec_spatch)
    out = cvehound._run_spatch('CVE-2021-46925', '/kernel', ['spatch'], 60, '/tmp', zygote=True)
    assert out == 'stdout from the fallback', what
    assert calls == ['zygote', 'exec']


def test_second_failure_is_the_rule(monkeypatch):
    """One retry, not a loop: a fallback that also fails is the rule's verdict."""
    monkeypatch.setattr(spatch_zygote, 'run', lambda *a, **k: (2, '', 'boom'))
    monkeypatch.setattr(cvehound, '_exec_spatch', lambda cmd, env, wall: (2, '', 'boom again'))
    with pytest.raises(SpatchError):
        cvehound._run_spatch('CVE-2021-46925', '/kernel', ['spatch'], 60, '/tmp', zygote=True)


def test_failure_on_the_stock_transport_is_an_error(monkeypatch):
    """Without the zygote a crash is spatch's own, not a transport fault."""
    monkeypatch.setattr(cvehound, '_exec_spatch', lambda cmd, env, wall: (-11, '', 'boom'))
    with pytest.raises(SpatchError):
        cvehound._run_spatch('CVE-2021-46925', '/kernel', ['spatch'], 60, '/tmp', zygote=False)


def test_fallback_timeout_is_classified(monkeypatch):
    """A timeout in the fallback is a timeout, not a bare TimeoutError."""

    def dead_zygote(cmd, env, workdir, wall_timeout, degrade=True):
        raise spatch_zygote.ZygoteDied('server exited mid-request')

    def slow_exec(cmd, env, wall_timeout):
        raise TimeoutError('killed at the wall')

    monkeypatch.setattr(spatch_zygote, 'run', dead_zygote)
    monkeypatch.setattr(cvehound, '_exec_spatch', slow_exec)
    with pytest.raises(SpatchTimeout):
        cvehound._run_spatch('CVE-2021-47314', '/kernel', ['spatch'], 60, '/tmp', zygote=True)


# --- a scan that dropped files: one rerun, and only when it can help ----------

TORN = (0, '', TORN_CACHE_STDERR)
OOM = (0, '', 'EXN: Out_of_memory in /k/net/mptcp/protocol.c\n' + SPATCH_TRAILER)
HIT = (0, 'hit', '')


@pytest.fixture
def cached_cmd(tmp_path):
    """A spatch command line with an AST cache holding a planted entry for the file."""
    prefix = tmp_path / 'ast'
    stem = prefix / 'k' / 'net' / 'mptcp' / 'protocol.c'
    stem.parent.mkdir(parents=True)
    for suffix in ('.ast_raw', '.depend_raw'):
        (stem.parent / (stem.name + suffix)).write_bytes(b'torn')
    return ['spatch', '--cache-prefix', str(prefix), '--very-quiet', '--cocci-file', 'r.cocci']


def scripted(monkeypatch, zygote=(), execs=()):
    """Replace both transports with scripted replies; record (transport, cmd) calls."""
    calls = []
    zygote, execs = list(zygote), list(execs)

    def reply(script, name, cmd):
        calls.append((name, list(cmd)))
        step = script.pop(0)
        if isinstance(step, BaseException):
            raise step
        return step

    monkeypatch.setattr(
        spatch_zygote,
        'run',
        lambda cmd, env, wd, wall, degrade=True: reply(zygote, 'zygote', cmd),
    )
    monkeypatch.setattr(cvehound, '_exec_spatch', lambda cmd, env, wall: reply(execs, 'exec', cmd))
    return calls


@pytest.mark.parametrize(
    ('mode', 'zygote', 'execs', 'transports', 'cache_kept'),
    [
        (None, [], [TORN, HIT], ['exec', 'exec'], False),
        ('auto', [TORN], [HIT], ['zygote', 'exec'], False),
        # The child started on the server's heap; one exec gets a fresh budget.
        ('auto', [OOM], [HIT], ['zygote', 'exec'], True),
        ('on', [TORN, HIT], [], ['zygote', 'zygote'], False),
    ],
    ids=[
        'torn-cache-on-exec',
        'torn-cache-on-the-zygote',
        'out-of-memory-in-a-zygote-child',
        'a-demanded-zygote-stays',
    ],
)
def test_a_rerun_that_can_help_runs_once(
    monkeypatch, cached_cmd, mode, zygote, execs, transports, cache_kept
):
    calls = scripted(monkeypatch, zygote=zygote, execs=execs)
    out = cvehound._run_spatch(
        'CVE-1', '/k', cached_cmd, 60, '/tmp', zygote=mode is not None, demanded=mode == 'on'
    )
    assert out == 'hit'
    assert [name for name, _ in calls] == transports
    assert ('--cache-prefix' in calls[-1][1]) is cache_kept
    # A torn entry left in place would drop the file again on every later scan.
    assert bool(list(pathlib.Path(cached_cmd[2]).rglob('*_raw'))) is cache_kept


@pytest.mark.parametrize(
    ('execs', 'raised', 'runs'),
    [
        # A fresh exec under the same cap would only repeat it.
        ([OOM], SpatchTruncated, 1),
        ([TORN, TORN], SpatchTruncated, 2),
        ([TORN, TimeoutError('killed at the wall')], SpatchTimeout, 2),
    ],
    ids=['out-of-memory', 'a-second-truncation', 'a-rerun-that-times-out'],
)
def test_a_failure_a_rerun_cannot_fix_is_the_answer(monkeypatch, cached_cmd, execs, raised, runs):
    calls = scripted(monkeypatch, execs=execs)
    with pytest.raises(raised) as excinfo:
        cvehound._run_spatch('CVE-1', '/k', cached_cmd, 60, '/tmp')
    assert type(excinfo.value) is raised
    assert len(calls) == runs
    if raised is SpatchTruncated:
        assert excinfo.value.retried is (runs == 2)


@pytest.mark.parametrize(
    ('dropped', 'cached', 'via_zygote', 'demanded', 'expected'),
    [
        # A cache fault drops the cache; the transport follows the zygote rule.
        ([('End_of_file', 'a.c')], True, True, False, ('/c', False)),
        ([('Sys_error("x: No space left on device")', 'a.c')], True, True, True, ('/c', True)),
        # A cache fault without a cache on the line has nothing to remove.
        ([('End_of_file', 'a.c')], False, False, False, None),
        # An inferred zygote's child reruns as one exec, keeping the cache.
        ([], True, True, False, (None, False)),
        # Nothing a rerun removes. No bad cache entry raises Invalid_argument.
        ([('Out_of_memory', 'a.c')], True, True, True, None),
        ([('Invalid_argument("index out of bounds")', 'a.c')], True, False, False, None),
        ([], True, False, False, None),
    ],
)
def test_truncation_retry_policy(dropped, cached, via_zygote, demanded, expected):
    cmd = ['spatch', *(['--cache-prefix', '/c'] if cached else []), '--cocci-file', 'r']
    assert cvehound.truncation_retry(cmd, dropped, via_zygote, demanded) == expected
