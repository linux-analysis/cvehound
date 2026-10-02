"""The zygote transport for spatch, selected by --zygote.

One `spatch --zygote` server per client process, spawned lazily on first use --
in a scan worker that is after install_sandbox(), so the server and every
request child inherit the confinement. The server holds the warm state (runtime
init, standard.iso parse, standard.h extraction) and forks a child per request.

Requests and status replies travel over the server's stdin/stdout as
length-prefixed frames; the request's own stdout/stderr are written by the
child to files in the caller-owned capture directory, so they survive a
wall-timeout SIGKILL, unlike a pipe. Frame layout (u32 big-endian lengths):
request = u32 field count, then per field u32 length + bytes, the fields being
capture dir, decimal env-entry count, env entries, spatch argv tail;
reply = u32 length + "exit <n> stdout=<bytes> stderr=<bytes>" or
"signal <n> name=<SIGNAME> stdout=<bytes> stderr=<bytes>", n being the host's
signal number and the sizes what the child left in each capture (-1 for one it
never created). That is protocol v2, which every request asks for with the env
entry COCCI_ZYGOTE_PROTO=2; a server that answers in the older format fails
its first request and counts as a build without --zygote.

The OCaml runtime reads OCAMLRUNPARAM once at server start, so the first
request's environment becomes the server's; each later request carries only the
entries that differ from it, which the server putenv()s into the request child.
Entries can be added or changed per request, never removed -- acceptable
because _spatch_env only ever adds to os.environ.
"""

import atexit
import contextlib
import os
import select
import struct
import subprocess
import tempfile
import time
from typing import IO

from cvehound.exception import SpatchError
from cvehound.util import killpg

V2_ENTRY = 'COCCI_ZYGOTE_PROTO=2'


def parse_reply(reply: str) -> tuple[int, dict[str, int]]:
    """A server reply as (subprocess returncode, capture sizes): the exit code,
    or minus the number of the signal that killed the child, and the bytes it
    left in each capture. ValueError on anything else, which the caller treats
    as a broken protocol."""
    kind, num, *rest = reply.split(' ')
    fields = dict(field.split('=', 1) for field in rest)
    code = int(num)
    if kind not in ('exit', 'signal') or (kind == 'signal' and code <= 0):
        raise ValueError(reply)
    if not {'stdout', 'stderr'} <= fields.keys():
        raise ValueError(reply)
    sizes = {name: int(fields[name]) for name in ('stdout', 'stderr')}
    return (code if kind == 'exit' else -code), sizes


class ZygoteDied(Exception):
    """The server exited or broke protocol; the caller should treat the
    request as a spatch crash."""


class ZygoteUnsupported(ZygoteDied):
    """This spatch cannot serve at all -- it failed its very first request.

    Distinct from ZygoteDied because the responses differ: a build without
    --zygote should cost a warning and one slow scan, while a server that dies
    after having worked is a real fault and must not be swallowed.
    """


class _Zygote:
    def __init__(self, spatch: str, env: dict[str, str]) -> None:
        self.spatch = spatch
        self.env = dict(env)
        self.owner_pid = os.getpid()
        # The server's own stderr goes to an unlinked scratch file, not
        # DEVNULL: a server that dies at startup -- a spatch built without
        # --zygote prints its usage error and exits -- says why only there,
        # and diagnostics() folds it into the ZygoteDied the caller sees.
        self.stderr: IO[bytes] = tempfile.TemporaryFile()  # noqa: SIM115 -- lives with the server
        self.proc = subprocess.Popen(
            [spatch, '--zygote'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            env=env,
            start_new_session=True,
        )

    def request(
        self, capture_dir: str, env_entries: list[str], argv_tail: list[str], deadline: float | None
    ) -> tuple[int, dict[str, int]]:
        fields = [capture_dir.encode(), str(len(env_entries)).encode()]
        fields += [e.encode() for e in env_entries]
        fields += [a.encode() for a in argv_tail]
        buf = bytearray(struct.pack('>I', len(fields)))
        for field in fields:
            buf += struct.pack('>I', len(field)) + field
        assert self.proc.stdin is not None and self.proc.stdout is not None
        try:
            self.proc.stdin.write(buf)
            self.proc.stdin.flush()
        except OSError as err:  # BrokenPipeError included: the server is gone
            raise self._died(str(err)) from err
        (length,) = struct.unpack('>I', self._read(4, deadline))
        reply = self._read(length, deadline).decode('utf-8', errors='replace')
        try:
            return parse_reply(reply)
        except ValueError as err:
            raise self._died(f'bad reply: {reply!r}') from err

    def _read(self, n: int, deadline: float | None) -> bytes:
        assert self.proc.stdout is not None
        fd = self.proc.stdout.fileno()
        buf = b''
        while len(buf) < n:
            try:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                        raise TimeoutError('zygote request deadline')
                chunk = os.read(fd, n - len(buf))
            except TimeoutError:  # also an OSError; keep it out of the wrap below
                raise
            except OSError as err:
                raise self._died(str(err)) from err
            if not chunk:
                raise self._died('server closed the reply stream')
            buf += chunk
        return buf

    def _died(self, msg: str) -> ZygoteDied:
        """A ZygoteDied carrying the tail of the server's own stderr -- for a
        server that broke protocol or died at startup (e.g. a spatch built
        without --zygote), that tail is the only diagnostic there is."""
        try:
            size = self.stderr.seek(0, os.SEEK_END)
            # One truncation policy: the exception this ends up in trims to
            # SpatchError.MAX_STDERR, so seek no shorter and no longer.
            self.stderr.seek(max(0, size - SpatchError.MAX_STDERR))
            tail = self.stderr.read().decode('utf-8', errors='replace').strip()
        except (OSError, ValueError):
            tail = ''
        return ZygoteDied(f'{msg}; server stderr: {tail}' if tail else msg)

    def kill(self) -> None:
        killpg(self.proc.pid)
        self.proc.wait()
        self.stderr.close()

    def close(self) -> None:
        if self.proc.poll() is None:
            assert self.proc.stdin is not None
            with contextlib.suppress(OSError):
                self.proc.stdin.close()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.kill()
                return
        self.stderr.close()

    def abandon(self) -> None:
        """Drop a fork-inherited copy without touching the parent's server.

        Only this process's duplicated pipe ends are closed; the server is the
        parent's child, so it is neither signalled nor waited on here.
        """
        for stream in (self.proc.stdin, self.proc.stdout, self.stderr):
            if stream is not None:
                with contextlib.suppress(OSError):
                    stream.close()


_zygote: _Zygote | None = None
# Binaries that have served at least one request, and binaries that failed
# their first one. Keyed by path because that is what identifies the build, and
# per-process because that is the scope a pool worker's server lives in.
_proven: set[str] = set()
_unsupported: set[str] = set()


def _close_zygote() -> None:
    global _zygote
    if _zygote is not None:
        if _zygote.owner_pid == os.getpid():
            _zygote.close()
        else:
            _zygote.abandon()
        _zygote = None


def run(
    cmd: list[str],
    env: dict[str, str],
    capture_dir: str,
    wall_timeout: int,
    degrade: bool = True,
) -> tuple[int, str, str]:
    """Run one spatch request through the per-process zygote.

    Returns (returncode, stdout, stderr) like a subprocess run would. On the
    wall deadline the whole server group is killed (children included) and
    TimeoutError is raised carrying, as its message, whatever the child wrote
    to its stderr capture before the kill. Any other failure mid-request also
    kills and resets the server: the reply stream may be desynced, so a server
    that saw one broken request is never reused.

    degrade allows the first failure against a binary that has never served a
    request to be reported as ZygoteUnsupported, so the caller can fall back
    instead of losing the CVE. Once a binary has served once it is never
    reported that way again -- a server that dies mid-scan is a fault, not a
    missing feature.
    """
    global _zygote
    if degrade and cmd[0] in _unsupported:
        raise ZygoteUnsupported(f'{cmd[0]} does not support --zygote')
    if _zygote is not None and (_zygote.owner_pid != os.getpid() or _zygote.spatch != cmd[0]):
        # A fork-inherited server belongs to the parent (two processes writing
        # frames to one pipe interleave them mid-frame); a different binary
        # needs its own warm state. _close_zygote picks abandon vs close.
        _close_zygote()
    if _zygote is None:
        _zygote = _Zygote(cmd[0], env)
    deadline = time.monotonic() + wall_timeout if wall_timeout else None
    # The server strips V2_ENTRY, so the child never sees it.
    env_entries = [f'{k}={v}' for k, v in env.items() if _zygote.env.get(k) != v] + [V2_ENTRY]
    try:
        returncode, sizes = _zygote.request(capture_dir, env_entries, cmd[1:], deadline)
        _check_capture_sizes(capture_dir, sizes)
        # The request child O_CREATs both capture files before it runs anything,
        # so on any reply a missing one is transport breakage. A missing stdout
        # read as '' would classify a broken run as "not vulnerable"; a missing
        # stderr would hide the EXN lines that say a file was dropped.
        stdout = _capture(capture_dir, 'zygote.stdout', required=True)
        stderr = _capture(capture_dir, 'zygote.stderr', required=True)
    except TimeoutError as err:
        _reset().kill()
        # The partial stderr capture is the only clue to where spatch wedged.
        raise TimeoutError(_capture(capture_dir, 'zygote.stderr')) from err
    except ZygoteDied as err:
        _reset().kill()
        if degrade and cmd[0] not in _proven:
            # It has never served a request, so this is what a build without
            # --zygote looks like: the server printed its usage error and quit,
            # and _died() folded that stderr into the message.
            _unsupported.add(cmd[0])
            raise ZygoteUnsupported(str(err)) from err
        raise
    except BaseException:
        # The exec transport kills the group on *any* exception (Ctrl-C
        # included); so must this one, or the in-flight request child keeps
        # burning cores and a half-read reply desyncs every later request.
        _reset().kill()
        raise
    _proven.add(cmd[0])
    return returncode, stdout, stderr


def _reset() -> _Zygote:
    """Detach the live server for its post-mortem: after any broken request it
    must never be reused, so the registry forgets it before the kill."""
    global _zygote
    server, _zygote = _zygote, None
    assert server is not None
    return server


def _check_capture_sizes(capture_dir: str, sizes: dict[str, int]) -> None:
    """The server measures the captures after reaping the child, so its sizes
    are what the child wrote; a capture that differs was cut short or is not
    this request's, and reading it as the answer is the transport's error."""
    for name, expected in sizes.items():
        path = os.path.join(capture_dir, f'zygote.{name}')
        actual = os.path.getsize(path) if os.path.exists(path) else -1
        if actual != expected:
            raise ZygoteDied(f'zygote.{name} is {actual} bytes, the server measured {expected}')


def _capture(capture_dir: str, name: str, required: bool = False) -> str:
    try:
        with open(os.path.join(capture_dir, name), encoding='utf-8', errors='replace') as fobj:
            return fobj.read()
    except OSError as err:
        if required:
            raise ZygoteDied(f'request left no readable {name}: {err}') from err
        return ''


atexit.register(_close_zygote)
