from typing import Any


class UnsupportedVersion(Exception):
    def __init__(self, spatch_version: int, cve: str, rule_version: int) -> None:
        # Convert version integer (e.g., 107) to dotted string (e.g., "1.0.7")
        # Version encoding: XYZ represents version X.Y.Z
        self.spatch_version = (
            f'{spatch_version // 100}.{(spatch_version // 10) % 10}.{spatch_version % 10}'
        )
        self.cve = cve
        self.rule_version = f'{rule_version // 100}.{(rule_version // 10) % 10}.{rule_version % 10}'


class SpatchNotFound(Exception):
    """No usable spatch binary: carries the message for the source that failed.

    find_spatch() reports every resolution failure this way -- an explicitly
    named binary that is missing, or nothing found at all -- so callers handle
    one exception instead of an exception plus a None return.
    """


class PcreGrepNotFound(Exception):
    """No grep understands -P, so a .grep rule cannot be evaluated at all.

    Raised instead of letting the exit status answer. grep says "no match" with
    1 and "I failed" with 2, and a grep without -P exits 2 -- BSD grep, which
    is /usr/bin/grep on macOS, prints "invalid option -- P". The caller treated
    every non-zero the same, so the rule reported the kernel clean without ever
    having looked at it: the one wrong answer a CVE check can give.

    GNU grep has -P (built --with-pcre); Homebrew installs it as ggrep rather
    than shadowing the system binary, which is why both names are tried.
    """


class SpatchError(Exception):
    """spatch exited non-zero: report what it said, not just how it was called.

    subprocess's CalledProcessError renders the full argv -- a kilobyte of
    include paths -- and drops stderr, so a crashed run is indistinguishable
    from any other. spatch is also silent under --very-quiet until it dies,
    and OCaml turns an uncaught exception (a full /tmp, say) into a bare
    exit code 2, which makes the captured stderr the only diagnosis there is.
    """

    #: stderr is unbounded (parse errors repeat per file); keep the tail, where
    #: the fatal message lands.
    MAX_STDERR = 2000

    def __init__(self, cve: str, kernel: str, returncode: int, stderr: str) -> None:
        self.cve = cve
        self.kernel = kernel
        self.returncode = returncode
        self.stderr = stderr
        tail = self.stderr_tail
        super().__init__(self._summary() + (f'\n{tail}' if tail else ' (no stderr)'))

    @property
    def stderr_tail(self) -> str:
        tail = self.stderr.strip()
        if len(tail) > self.MAX_STDERR:
            tail = '...' + tail[-self.MAX_STDERR :]
        return tail

    def _summary(self) -> str:
        return f'spatch failed with exit code {self.returncode} on {self.cve} in {self.kernel}'

    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        # Raised inside ProcessPoolExecutor workers, so it has to survive a
        # pickle round trip: the default reduce replays __init__ with the
        # single formatted message BaseException recorded in .args.
        return (self.__class__, (self.cve, self.kernel, self.returncode, self.stderr))


class SpatchTimeout(SpatchError):
    """A rule blew its time budget: which budget, and on what file.

    Subclasses SpatchError so callers that only care the rule failed keep
    working. The distinction is worth drawing because a timeout is never an
    environment problem -- it is the rule, and the fix is a cheaper pattern
    (docs/WRITING_RULES.md -> "Rule 8: Keep the grep query selective").

    Two budgets produce it. spatch's own --timeout counts CPU-seconds inside the
    matching engine and usually names the file it gave up on; the outer
    wall-clock watchdog counts everything, including the phases --timeout cannot
    see, and names nothing. `files` is empty whenever spatch did not say, which
    is not the same as "no file was to blame".
    """

    def __init__(
        self,
        cve: str,
        kernel: str,
        returncode: int,
        stderr: str,
        timeout: int,
        files: list[str] | None = None,
        wall: bool = False,
    ) -> None:
        self.timeout = timeout
        self.files = files or []
        self.wall = wall
        super().__init__(cve, kernel, returncode, stderr)

    def _summary(self) -> str:
        budget = f'{self.timeout}s of wall time' if self.wall else f'{self.timeout} CPU-seconds'
        where = f' on {", ".join(self.files)}' if self.files else ''
        return f'{self.cve}: spatch exceeded its budget of {budget}{where} in {self.kernel}'

    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        return (self.__class__, super().__reduce__()[1] + (self.timeout, self.files, self.wall))


class SpatchTruncated(SpatchError):
    """spatch exited 0 having dropped files: the scan is incomplete, not clean.

    Handed a directory, spatch catches any exception raised on one file, prints
    `EXN: <exn> in <file>`, skips the file and still exits 0, so a file it never
    matched against reads exactly like a file with nothing to report. Read as
    "not vulnerable" that is the one wrong answer a check can give, and a cached
    one is repeated by every later run that shares the cache.

    Subclasses SpatchError so every caller that already treats an engine failure
    as "no verdict" does so here too. The distinction worth drawing is that this
    is the environment's, not the rule's -- a torn AST-cache entry, a full disk,
    a memory cap -- where a SpatchTimeout is the rule's. `dropped` pairs each
    exception with the file it cost; empty means spatch printed its trailer
    without naming one, which is still not "complete". `retried` says the scan
    had already been rerun once before giving this answer.
    """

    def __init__(
        self,
        cve: str,
        kernel: str,
        returncode: int,
        stderr: str,
        dropped: list[tuple[str, str]] | None = None,
        retried: bool = False,
    ) -> None:
        self.dropped = [tuple(pair) for pair in dropped or []]
        self.retried = retried
        super().__init__(cve, kernel, returncode, stderr)

    @property
    def files(self) -> list[str]:
        return sorted({file for _exn, file in self.dropped})

    @property
    def kinds(self) -> list[str]:
        return sorted({exn for exn, _file in self.dropped})

    def _summary(self) -> str:
        count = len(self.files)
        what = f'{count} file{"" if count == 1 else "s"}' if count else 'files it did not name'
        where = f' ({", ".join(self.files)})' if self.files else ''
        why = f': {", ".join(self.kinds)}' if self.kinds else ''
        again = ' after one retry' if self.retried else ''
        return f'{self.cve}: spatch dropped {what}{where} mid-scan in {self.kernel}{why}{again}'

    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        return (self.__class__, super().__reduce__()[1] + (self.dropped, self.retried))


class SandboxError(Exception):
    """The sandbox could not be installed, or could not be trusted once it was.

    Raised for two situations that both have to stop the scan. Under --sandbox
    strict, any degradation at all. And always, a self-test that failed after
    landlock_restrict_self: the policy is one path too tight, Landlock cannot be
    undone, and continuing would report a clean kernel rather than an error --
    spatch answers "0 files match" whether a tree is clean or unreadable.
    """

    def __init__(self, reasons: list[str]) -> None:
        self.reasons = reasons
        super().__init__(self._summary())

    def _summary(self) -> str:
        return 'sandbox failed:\n  ' + '\n  '.join(self.reasons)

    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        return (self.__class__, (self.reasons,))


class GitError(Exception):
    """git could not answer: not a repository, an unknown revision, a failed command.

    One exception for every git failure the CLI can hit, carrying git's own
    stderr as the message. The distinction the callers care about is "this
    tree has no usable history" versus "this revision is not here", and both
    are decided from the message the user reads, not from the type.
    """
