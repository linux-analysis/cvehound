#!/usr/bin/env python3

"""Bound what a scan may touch, the way the timeouts bound how long it may run.

A scan hands an untrusted source tree to spatch -- a large OCaml binary driven by
.cocci rules that `cvehound update` fetches over the network -- and spatch is not
a leaf process. Traced under this tool's own argv it shells out:

    /bin/sh -c "cd DIR > /dev/null; git grep -l -w TOKEN -- '*.[ch]'"   per rule token
    /bin/sh -c "find DIR -type f -name '*.[ch]' ..."                    non-git trees
    /bin/sh -c "rm -rf TMPDIR"                                          --tmp-dir cleanup
    /bin/sh -c "diff -u -p ..."                                         on a match

None of that needs the user's ssh keys, their home directory, or a socket. Landlock
takes away the filesystem and TCP; seccomp takes away the syscalls Landlock cannot
express (UDP, netlink, io_uring, ptrace, namespaces). Both are inherited across fork
and execve, so installing once in the parent covers the worker pool, spatch, and
everything spatch runs.

Two properties drive the shape of this module:

Landlock is irreversible. Every way of *not* sandboxing has to be decided before
landlock_restrict_self, which is why apply() degrades but self_test() aborts.

A too-tight policy is silent. Denied a path it needs, spatch reports "0 files match"
and exits 0 -- a missed CVE that looks exactly like a clean tree. That is the failure
mode this module exists to avoid, so self_test() proves the allowed set positively
rather than trusting that the rules were built right.
"""

import ctypes
import logging
import os
import platform
import site
import sys
import tempfile
from dataclasses import dataclass, field

from cvehound import check_git_prefilter
from cvehound.exception import SandboxError

# The constants below are uapi values with no Python equivalent, so they have to
# be written out. tests/test_15_sandbox.py checks every one of them against this
# machine's own kernel headers via the C preprocessor, so a transcription error
# fails the suite rather than silently confining the wrong thing.
#
# Same numbers on every architecture (the syscalls were added in one block).
_NR_LANDLOCK_CREATE_RULESET = 444
_NR_LANDLOCK_ADD_RULE = 445
_NR_LANDLOCK_RESTRICT_SELF = 446

_PR_SET_NO_NEW_PRIVS = 38
_LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
_LANDLOCK_RULE_PATH_BENEATH = 1

# LANDLOCK_ACCESS_FS_* in uapi bit order; the index is the bit.
_FS_RIGHTS = (
    'EXECUTE',
    'WRITE_FILE',
    'READ_FILE',
    'READ_DIR',
    'REMOVE_DIR',
    'REMOVE_FILE',
    'MAKE_CHAR',
    'MAKE_DIR',
    'MAKE_REG',
    'MAKE_SOCK',
    'MAKE_FIFO',
    'MAKE_BLOCK',
    'MAKE_SYM',
    'REFER',
    'TRUNCATE',
    'IOCTL_DEV',
)
FS = {name: 1 << bit for bit, name in enumerate(_FS_RIGHTS)}

# Highest FS bit an ABI knows. Asking for a bit the running kernel has never heard
# of fails the whole ruleset, so the request is always clamped to this -- including
# on a kernel newer than the table, where the right move is to ask for what we
# understand rather than to guess at what was added.
_ABI_FS_LAST = {1: 12, 2: 13, 3: 14, 4: 14, 5: 15}
_ABI_FS_LAST_KNOWN = max(_ABI_FS_LAST.values())

# Rights that mean nothing on a non-directory. Landlock rejects the whole rule with
# EINVAL rather than ignoring them, so a rule for /dev/null has to be masked down.
_FILE_RIGHTS = FS['EXECUTE'] | FS['WRITE_FILE'] | FS['READ_FILE'] | FS['TRUNCATE'] | FS['IOCTL_DEV']

_NET_BIND_TCP = 1 << 0
_NET_CONNECT_TCP = 1 << 1
_SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0
_SCOPE_SIGNAL = 1 << 1

# landlock_ruleset_attr grew a field at a time, and the kernel rejects a struct
# longer than the one it knows with non-zero tail bytes. Send exactly as much as
# the running ABI can read.
_ATTR_SIZE_FS = 8
_ATTR_SIZE_NET = 16
_ATTR_SIZE_SCOPED = 24

_NR_SECCOMP = {'x86_64': 317, 'aarch64': 277}
_AUDIT_ARCH = {'x86_64': 0xC000003E, 'aarch64': 0xC00000B7}

_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_JMP_JGE_K = 0x35
_BPF_RET_K = 0x06

_X32_SYSCALL_BIT = 0x40000000
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_SET_MODE_FILTER = 1
_SECCOMP_FILTER_FLAG_TSYNC = 1

# Offsets into struct seccomp_data: nr, arch, then args[0] after the 8-byte
# instruction pointer. Little-endian, so args[0]'s low word is at its base.
_OFF_NR = 0
_OFF_ARCH = 4
_OFF_ARG0 = 16

_AF_UNIX = 1
_EPERM = 1
_EAFNOSUPPORT = 97

# Denied outright. Every one of these is something Landlock structurally cannot
# reach -- it governs files and TCP, not syscall families -- and none of them appear
# in a traced spatch subtree, whose whole vocabulary is 58 syscalls. The ones that
# matter most here are the socket families (Landlock sees TCP only, so UDP is an
# open exfil path), io_uring (its own submission path has historically bypassed
# per-syscall checks), and ptrace (Landlock stops crossing *out* of a domain, not
# one sandboxed process reading another's memory).
_DENY = {
    'x86_64': {
        'ptrace': 101,
        'process_vm_readv': 310,
        'process_vm_writev': 311,
        'unshare': 272,
        'setns': 308,
        'mount': 165,
        'umount2': 166,
        'pivot_root': 155,
        'chroot': 161,
        'bpf': 321,
        'perf_event_open': 298,
        'userfaultfd': 323,
        'io_uring_setup': 425,
        'io_uring_enter': 426,
        'io_uring_register': 427,
        'add_key': 248,
        'request_key': 249,
        'keyctl': 250,
        'init_module': 175,
        'finit_module': 313,
        'delete_module': 176,
        'kexec_load': 246,
        'kexec_file_load': 320,
    },
    'aarch64': {
        'ptrace': 117,
        'process_vm_readv': 270,
        'process_vm_writev': 271,
        'unshare': 97,
        'setns': 268,
        'mount': 40,
        'umount2': 39,
        'pivot_root': 41,
        'chroot': 51,
        'bpf': 280,
        'perf_event_open': 241,
        'userfaultfd': 282,
        'io_uring_setup': 425,
        'io_uring_enter': 426,
        'io_uring_register': 427,
        'add_key': 217,
        'request_key': 218,
        'keyctl': 219,
        'init_module': 105,
        'finit_module': 273,
        'delete_module': 106,
        'kexec_load': 104,
        'kexec_file_load': 294,
    },
}
_NR_SOCKET = {'x86_64': 41, 'aarch64': 198}

_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long


class _RulesetAttr(ctypes.Structure):
    _fields_ = (
        ('handled_access_fs', ctypes.c_uint64),
        ('handled_access_net', ctypes.c_uint64),
        ('scoped', ctypes.c_uint64),
    )


class _PathBeneathAttr(ctypes.Structure):
    # Packed in the uapi header, and landlock_add_rule takes no size argument, so
    # the 12-byte layout is not negotiable -- natural alignment would send 16 and
    # put parent_fd in the padding.
    _pack_ = 1
    _layout_ = 'ms'
    _fields_ = (('allowed_access', ctypes.c_uint64), ('parent_fd', ctypes.c_int32))


class _SockFilter(ctypes.Structure):
    _fields_ = (
        ('code', ctypes.c_uint16),
        ('jt', ctypes.c_uint8),
        ('jf', ctypes.c_uint8),
        ('k', ctypes.c_uint32),
    )


class _SockFprog(ctypes.Structure):
    _fields_ = (('len', ctypes.c_uint16), ('filter', ctypes.POINTER(_SockFilter)))


@dataclass(frozen=True)
class SandboxPolicy:
    """The three access classes, as absolute paths. Missing paths are dropped."""

    read: tuple[str, ...] = ()
    read_exec: tuple[str, ...] = ()
    write: tuple[str, ...] = ()


@dataclass(frozen=True)
class SandboxStatus:
    """What actually got installed, for the log line and for --sandbox=strict."""

    landlock_abi: int = 0
    seccomp: bool = False
    degraded: tuple[str, ...] = field(default_factory=tuple)

    def summary(self) -> str:
        parts = []
        if self.landlock_abi:
            parts.append(f'landlock ABI {self.landlock_abi}')
        if self.seccomp:
            parts.append('seccomp')
        line = 'sandbox: ' + (' + '.join(parts) or 'off')
        if self.degraded:
            line += ' (' + '; '.join(self.degraded) + ')'
        return line


def _syscall(nr: int, *args: object) -> int:
    ctypes.set_errno(0)
    return int(_libc.syscall(ctypes.c_long(nr), *args))


def landlock_abi() -> int:
    """The kernel's Landlock ABI, or 0 when Landlock is unavailable.

    A negative return means the syscall exists but the LSM is not enabled (ENOSYS
    when the kernel lacks it, EOPNOTSUPP when it was left out of the boot-time lsm=
    list), and both mean the same thing to us. Off Linux the number would name a
    different syscall entirely, so it is never dialled.
    """
    if sys.platform != 'linux':
        return 0
    rc = _syscall(
        _NR_LANDLOCK_CREATE_RULESET,
        None,
        ctypes.c_size_t(0),
        ctypes.c_uint32(_LANDLOCK_CREATE_RULESET_VERSION),
    )
    return rc if rc > 0 else 0


def fs_mask(abi: int) -> int:
    """Every FS right the given ABI understands."""
    last = _ABI_FS_LAST.get(abi, _ABI_FS_LAST_KNOWN)
    return (1 << (last + 1)) - 1


def _ruleset_attr(abi: int) -> tuple[_RulesetAttr, int]:
    attr = _RulesetAttr(fs_mask(abi), 0, 0)
    size = _ATTR_SIZE_FS
    if abi >= 4:
        # No net rules are ever added, and a handled access with no rule allowing
        # it is a denial: this is how "no network" is spelled.
        attr.handled_access_net = _NET_BIND_TCP | _NET_CONNECT_TCP
        size = _ATTR_SIZE_NET
    if abi >= 6:
        attr.scoped = _SCOPE_ABSTRACT_UNIX_SOCKET | _SCOPE_SIGNAL
        size = _ATTR_SIZE_SCOPED
    return attr, size


def _rights_for(path: str, access: int) -> int:
    """The subset of `access` that Landlock will accept for this kind of file."""
    if not os.path.isdir(path):
        access &= _FILE_RIGHTS
    return access


def build_policy(
    kernel: str,
    rules_dir: str,
    spatch: str,
    metadata: str | None = None,
    astcache: str | None = None,
    extra_read: tuple[str, ...] = (),
) -> SandboxPolicy:
    """The least a scan can run with, derived from resolved paths only.

    Nothing here is a guess about where things live: the interpreter comes from
    sys.base_prefix (uv, pyenv and conda all put it outside the venv), spatch's
    payload from the realpath of the binary (standard.h and standard.iso are its
    siblings), and the rules from resolve_content(). The report file is deliberately
    absent -- see install(), which pre-opens it instead of granting its directory.

    extra_read is for the git modes: the repository's git dir (and any object
    store it borrows through alternates), which git has to read after the lock
    to answer where a fix is in the history -- and which, under `scan --rev`,
    is not beneath `kernel`, because `kernel` is then a materialized temp tree.
    """
    read = [
        kernel,
        rules_dir,
        '/etc',  # ld.so.cache, gitconfig, cvehound.ini
        '/proc/self',  # spatch readlinks /proc/self/exe to find its payload
        '/sys/devices/system/cpu',  # spatch reads cpu/online to size its pool
        *extra_read,
    ]
    if metadata:
        read.append(metadata)

    # Interpreter, libraries, and everywhere cvehound itself might be imported
    # from. All of it is needed twice over: once for the console-script shebang,
    # and again under forkserver/spawn (the Linux default from 3.14), where every
    # worker re-execs python and re-imports cvehound. A gap here is not a missed
    # detection but a PermissionError that takes the whole pool down.
    read_exec = [
        '/usr',
        '/bin',
        '/sbin',
        '/lib',
        '/lib64',
        *_spatch_payload_dirs(spatch),
        os.path.realpath(sys.base_prefix),
        os.path.realpath(sys.prefix),
        # The package's own parent, which an editable install or `python -m
        # cvehound` from a checkout puts outside every prefix above.
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        site.getusersitepackages(),
        *site.getsitepackages(),
        *_import_roots(),
    ]

    # /tmp is not negotiable: coccinelle hardcodes /tmp/cocci_small_output-*,
    # /tmp/.parmap.* and /tmp/nothing, and ignores TMPDIR for them. /dev/shm is the
    # ProcessPoolExecutor's -- multiprocessing.SemLock is a POSIX named semaphore.
    write = [
        tempfile.gettempdir(),
        '/tmp',
        '/dev/shm',
        '/dev/null',
        '/dev/zero',
        '/dev/urandom',
        '/dev/random',
    ]
    # The experimental AST cache is read and written by every spatch; left out
    # of the grant it would not fail the scan, just quietly never populate.
    # Resolved (and created) by util.astcache_dir(), like every path above.
    if astcache:
        write.append(astcache)

    return SandboxPolicy(
        read=_clean(read),
        read_exec=_clean(read_exec),
        write=_clean(write),
    )


def _import_roots() -> list[str]:
    """sys.path, minus the two entries that would give the whole sandbox away.

    `python -m cvehound` puts the working directory on sys.path as '.', so sweeping
    it up wholesale grants read and execute over whatever directory the tool was run
    from -- routinely $HOME, which is most of what the sandbox exists to keep out.
    The package's own parent is granted separately and unconditionally, so dropping
    these two costs an import nothing.
    """
    excluded = {os.path.abspath(os.getcwd()), os.path.abspath(os.path.expanduser('~'))}
    roots = []
    for entry in sys.path:
        if not entry:
            continue
        resolved = os.path.abspath(entry)
        if resolved not in excluded and os.path.isdir(resolved):
            roots.append(resolved)
    return roots


def _spatch_payload_dirs(spatch: str) -> list[str]:
    """Where this spatch reads standard.h and standard.iso, in coccinelle's own order.

    globals/cocciconfig.ml resolves the payload as $COCCINELLE_HOME, else the
    binary's directory when it holds standard.iso (the bundled wheel's layout),
    else <prefix>/<libdir>/coccinelle beside <prefix>/bin (make install, an opam
    switch). Granting only the binary's directory read the wheel right and denied
    every installed build its standard.h: `Sys_error ... Permission denied`, exit 2,
    on every rule. _clean drops whichever of these does not exist.
    """
    bindir = os.path.dirname(os.path.realpath(spatch))
    prefix = os.path.dirname(bindir)
    dirs = [
        bindir,
        os.path.join(prefix, 'lib', 'coccinelle'),
        os.path.join(prefix, 'lib64', 'coccinelle'),
    ]
    home = os.environ.get('COCCINELLE_HOME')
    if home:
        dirs.insert(0, os.path.realpath(home))
    return dirs


def _clean(paths: list[str]) -> tuple[str, ...]:
    """Absolute, deduplicated, and filtered to what exists -- order preserved."""
    return tuple(dict.fromkeys(os.path.abspath(p) for p in paths if p and os.path.exists(p)))


def build_seccomp_program(arch: str) -> list[tuple[int, int, int, int]]:
    """Assemble the classic-BPF filter as (code, jt, jf, k) tuples.

    Kept free of ctypes so the assembly can be asserted on directly. Every jump is
    forward, because classic BPF has no backward branches; the three terminals and
    the socket() check therefore sit at the end, and the label arithmetic below is
    what keeps the offsets in the 8-bit jt/jf fields.
    """
    deny = sorted(_DENY[arch].values())
    n = len(deny)
    # Label layout after the n deny comparisons: allow at 5+n is reached by
    # falling off the end of them, so only the three jumped-to labels are named.
    l_deny, l_kill, l_sock = 6 + n, 7 + n, 8 + n
    prog: list[tuple[int, int, int, int]] = []

    def jump(label: int) -> int:
        """Offset from the instruction about to be appended to `label`."""
        return label - len(prog) - 1

    # The architecture check has to come first and has to be fatal. Without it a
    # process could re-enter through the compat ABI, where the same numbers mean
    # different syscalls and the deny-list below would wave them through.
    prog.append((_BPF_LD_W_ABS, 0, 0, _OFF_ARCH))
    prog.append((_BPF_JMP_JEQ_K, 0, jump(l_kill), _AUDIT_ARCH[arch]))
    prog.append((_BPF_LD_W_ABS, 0, 0, _OFF_NR))
    prog.append((_BPF_JMP_JGE_K, jump(l_kill), 0, _X32_SYSCALL_BIT))
    prog.append((_BPF_JMP_JEQ_K, jump(l_sock), 0, _NR_SOCKET[arch]))
    for nr in deny:
        prog.append((_BPF_JMP_JEQ_K, jump(l_deny), 0, nr))
    prog.append((_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW))
    prog.append((_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | _EPERM))
    prog.append((_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS))
    # socket(): the family is a scalar argument, so it can be filtered without
    # dereferencing anything. AF_UNIX stays because the worker pool needs it.
    prog.append((_BPF_LD_W_ABS, 0, 0, _OFF_ARG0))
    prog.append((_BPF_JMP_JEQ_K, 0, 1, _AF_UNIX))
    prog.append((_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW))
    prog.append((_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | _EAFNOSUPPORT))
    return prog


def _set_no_new_privs() -> None:
    if _libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'prctl(PR_SET_NO_NEW_PRIVS) failed')


def _install_landlock(policy: SandboxPolicy, abi: int) -> None:
    attr, size = _ruleset_attr(abi)
    mask = fs_mask(abi)
    fd = _syscall(
        _NR_LANDLOCK_CREATE_RULESET,
        ctypes.byref(attr),
        ctypes.c_size_t(size),
        ctypes.c_uint32(0),
    )
    if fd < 0:
        raise OSError(ctypes.get_errno(), 'landlock_create_ruleset failed')
    try:
        ro = FS['READ_FILE'] | FS['READ_DIR']
        for paths, access in (
            (policy.read, ro),
            (policy.read_exec, ro | FS['EXECUTE']),
            (policy.write, mask),
        ):
            for path in paths:
                _add_path(fd, path, _rights_for(path, access & mask))
        _set_no_new_privs()
        if _syscall(_NR_LANDLOCK_RESTRICT_SELF, ctypes.c_int(fd), ctypes.c_uint32(0)) != 0:
            raise OSError(ctypes.get_errno(), 'landlock_restrict_self failed')
    finally:
        os.close(fd)


def _add_path(ruleset_fd: int, path: str, access: int) -> None:
    if not access:
        return
    try:
        path_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except OSError:
        # A path that vanished between build_policy() and here is not worth
        # failing over; self_test() covers the ones we actually depend on.
        return
    try:
        attr = _PathBeneathAttr(access, path_fd)
        rc = _syscall(
            _NR_LANDLOCK_ADD_RULE,
            ctypes.c_int(ruleset_fd),
            ctypes.c_int(_LANDLOCK_RULE_PATH_BENEATH),
            ctypes.byref(attr),
            ctypes.c_uint32(0),
        )
        if rc != 0:
            raise OSError(ctypes.get_errno(), f'landlock_add_rule failed for {path}')
    finally:
        os.close(path_fd)


def _install_seccomp() -> bool:
    # platform.machine() reports the *kernel*, so a 32-bit interpreter on an
    # x86_64 kernel also says 'x86_64'. Installing the 64-bit filter there would
    # fail its own AUDIT_ARCH check on every syscall and SIGSYS the tool dead.
    arch = platform.machine()
    if sys.platform != 'linux' or arch not in _DENY or sys.maxsize <= 2**32:
        return False
    prog = build_seccomp_program(arch)
    filters = (_SockFilter * len(prog))(*[_SockFilter(*insn) for insn in prog])
    fprog = _SockFprog(len(prog), filters)
    _set_no_new_privs()
    rc = _syscall(
        _NR_SECCOMP[arch],
        ctypes.c_ulong(_SECCOMP_SET_MODE_FILTER),
        ctypes.c_ulong(_SECCOMP_FILTER_FLAG_TSYNC),
        ctypes.byref(fprog),
    )
    if rc != 0:
        raise OSError(ctypes.get_errno(), 'seccomp(SECCOMP_SET_MODE_FILTER) failed')
    return True


def apply(policy: SandboxPolicy) -> SandboxStatus:
    """Install what this kernel supports; report what it could not.

    Degrading is this function's job because nothing here is irreversible until
    landlock_restrict_self, and by then there is no way back. The two mechanisms
    degrade independently: a kernel without Landlock still gets the syscall filter.
    """
    degraded: list[str] = []

    abi = landlock_abi()
    if abi < 1:
        abi = 0
        degraded.append('landlock unavailable on this kernel')
    else:
        try:
            _install_landlock(policy, abi)
        except OSError as err:
            abi = 0
            degraded.append(f'landlock not installed: {err}')

    seccomp = False
    try:
        seccomp = _install_seccomp()
        if not seccomp:
            degraded.append(f'no seccomp syscall table for {platform.machine()}')
    except OSError as err:
        degraded.append(f'seccomp not installed: {err}')

    return SandboxStatus(landlock_abi=abi, seccomp=seccomp, degraded=tuple(degraded))


def self_test(policy: SandboxPolicy, kernel: str, rules_dir: str, spatch: str) -> None:
    """Prove the allowed set still works, now that it cannot be widened.

    This exists because the failure it catches is invisible: handed a tree it
    cannot read, spatch prints "0 files match" and exits 0, so a policy that is one
    path too tight reports a clean kernel instead of an error.

    It reads the policy rather than a list of its own, so that a path added to
    build_policy() is covered the moment it is granted. A hand-written list would
    drift, and the whole point of this function is catching drift.
    """
    failures: list[str] = []

    for path in policy.read + policy.read_exec:
        failures.extend(_unreadable(path))
    for path in policy.write:
        failures.extend(_unwritable(path))

    # The loops above prove what the policy granted. The other way to be one path
    # too tight is for build_policy() to have dropped one -- it does that silently
    # for anything that does not exist -- which reads the same at scan time: no
    # grant, nothing readable, "0 files match".
    granted = {*policy.read, *policy.read_exec, *policy.write}
    for label, path in (('kernel tree', kernel), ('rules', rules_dir)):
        if os.path.abspath(path) not in granted:
            failures.append(f'the {label} at {path} was never granted')
    if not os.access(spatch, os.X_OK):
        failures.append(f'cannot execute spatch at {spatch}')
    failures.extend(check_git_prefilter(kernel))

    if failures:
        raise SandboxError(failures)


def _unreadable(path: str) -> list[str]:
    """Whether the granted path can still be opened for what it is."""
    try:
        if os.path.isdir(path):
            with os.scandir(path) as entries:
                next(iter(entries), None)
        else:
            with open(path, 'rb'):
                pass
    except OSError as err:
        return [f'cannot read {path}: {err}']
    return []


def _unwritable(path: str) -> list[str]:
    """Whether the granted path can still be written.

    Only directories are probed. The character devices in the write set (/dev/null
    and friends) are granted for spatch and the pool to open, and writing to them
    here would prove nothing a mode bit does not already guarantee.
    """
    if not os.path.isdir(path):
        return []
    try:
        fd, name = tempfile.mkstemp(prefix='cvehound-sandbox-', dir=path)
        os.write(fd, b'x')
        os.close(fd)
        os.unlink(name)
    except OSError as err:
        return [f'cannot write in {path}: {err}']
    return []


def install(
    kernel: str,
    rules_dir: str,
    spatch: str,
    metadata: str | None = None,
    astcache: str | None = None,
    strict: bool = False,
    extra_read: tuple[str, ...] = (),
) -> SandboxStatus:
    """Build, apply and verify. The only entry point the CLI needs.

    strict turns every degradation into a refusal to scan, for callers who would
    rather not run at all than run unconfined.
    """
    policy = build_policy(kernel, rules_dir, spatch, metadata, astcache, extra_read)
    status = apply(policy)
    if status.degraded and strict:
        raise SandboxError(list(status.degraded))
    if status.landlock_abi:
        self_test(policy, kernel, rules_dir, spatch)
    logging.info(status.summary())
    return status
