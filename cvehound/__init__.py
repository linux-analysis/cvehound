#!/usr/bin/env python3

import logging
import os
import shutil
import signal
import subprocess
import tempfile
from typing import Any

from cvehound import condition, spatch_zygote
from cvehound.config import Config
from cvehound.exception import (
    SpatchError,
    SpatchNotFound,
    SpatchTimeout,
    SpatchTruncated,
    UnsupportedVersion,
)
from cvehound.kbuild import KbuildParser
from cvehound.util import (
    astcache_dir,
    astcache_evict,
    find_spatch,
    fix_date_str,
    get_cves_metadata,
    get_rule_cves,
    get_spatch_version,
    get_srcarch,
    is_cache_fault,
    killpg,
    parse_coccinelle_output,
    parse_spatch_drops,
    parse_spatch_fatal,
    parse_spatch_summary,
    parse_spatch_timeout,
    parse_spatch_truncation,
    pcre_grep,
    resolve_zygote,
    spatch_features,
)

__VERSION__ = '1.8.0'

# The transport and engine verdicts get their own logger: they are rare and they
# are the only record of why a scan was rerun, so a harness that silences the
# per-check chatter on the root logger can still keep these.
log = logging.getLogger('cvehound.spatch')

RuleMetadata = dict[str, Any]

# Sources that become object files, i.e. the ones the Kbuild map can describe.
COMPILED_SUFFIXES = ('.c', '.S', '.s', '.rs')

# Force-included into every spatch run when the tree has it; the test harness
# mirrors this probe when it materializes mini-trees (cvehound/oracle/kerneltree.py).
KCONFIG_H = 'include/linux/kconfig.h'

# CPU-seconds inside the matching engine, per work unit -- and each of those
# three words matters. CPU, because coccinelle arms ITIMER_VIRTUAL, so an
# oversubscribed machine does not trip it. Matching engine, because the timer
# wraps Cocci.full_engine only: the ~3s of iso loading and rule parsing, and any
# wait on I/O, are outside it. Work unit, because given a file list spatch
# treats the whole list as one, and only a directory (--all-files) splits per
# file.
#
# 60 against a worst measured file of 0.5 CPU-seconds is margin for the two
# things that move billed CPU -- machine load and core speed -- not for
# expensive rules. docs/WRITING_RULES.md -> "The rule exceeds its time budget"
# carries the numbers.
SPATCH_TIMEOUT = 60

# The outer bound, and the only one that sees what a CPU budget structurally
# cannot: a stalled read, a deadlocked parmap child, a rule parse that never
# returns. It is also the coarser statement of the same standard -- no single
# spatch run has any business taking five minutes, whole-tree scan included, and
# one that does is a rule to rewrite rather than a budget to raise. The slowest
# --all-files scan of the whole rule set measures 43s wall / 37s CPU, so this
# leaves ~7x for slower hardware. 0 disables it, as it does for spatch.
SPATCH_WALL_TIMEOUT = 300

# spatch is OCaml, and its cost on a rule's own files is dominated by allocating
# and collecting the parsed AST. space_overhead is how much garbage the major
# collector tolerates before it works, so raising it buys wall-clock with memory
# -- and the memory it spends is small at this shape: peak RSS per spatch stays
# ~40-46MB whatever the setting, because a rule sees a handful of files. Measured
# against the bundled cvehound-spatch build (1.3.2 on OCaml 5.3) on the fast
# suite (idle 32-thread box, --no-result-cache, paired runs): 56.0s
# default, 49.4s at o=800, 47.9s at o=1600, 47.2s at o=3200 -- so 1600 sits where
# the curve flattens. Do not raise the minor heap (s=) with it: every variant
# tried was slower, and a large one triples system time under 32-way concurrency.
#
# Whole-tree scans (--all-files) barely move: handed a directory spatch spends
# its time on the token prefilter, scanning every file in the tree for the
# rule's literals, and parses almost nothing. There is no AST there to collect.
SPATCH_OCAMLRUNPARAM = 'o=1600'


def evaluate_file_condition(
    logic: str | None, relpath: str, srcarch: str, config: Config | None
) -> tuple[str, bool | None]:
    """Evaluate one file's Kbuild CONFIG condition against a .config.

    @logic is the raw condition from the Kbuild map: None when the file is
    unknown to the parser, '' when the file is built unconditionally.
    Returns the printable condition and the affected verdict; the verdict
    is None when there is no .config to evaluate against.
    """
    if relpath.startswith('arch/') and not relpath.startswith('arch/' + srcarch + '/'):
        # Sources of another architecture are never built into this kernel.
        text, affected = 'False', False
    elif logic is None:
        # Unknown to the parser: assume built (prefer a false positive).
        text, affected = 'unknown', True
    elif logic == '':
        text, affected = 'True', True
    else:
        # The verdict comes from the raw condition: simplification is only
        # for the printed form, so it can never change what a scan reports.
        expr = condition.parse(logic)
        text = str(condition.simplify(expr))
        affected = config is not None and condition.evaluate(expr, config)

    return (text, affected if config is not None else None)


def _spatch_env(kernel: str | None = None) -> dict[str, str]:
    """The environment for a spatch child: ours, plus our GC and git defaults.

    A caller who has already said something about the OCaml runtime keeps it
    untouched -- the tuning is a default, not a policy. CAMLRUNPARAM counts as
    saying something: the runtime reads OCAMLRUNPARAM first and only falls back
    to it, so setting ours unconditionally would silently void theirs.

    The git half is about reproducibility. Handed a directory, spatch prefilters
    it by shelling out to `git grep` once per rule token, and that git reads the
    user's ~/.gitconfig and /etc/gitconfig -- so a grep.* or pathspec setting
    there can change what a scan finds, on one machine and not another. Dropping
    both makes the prefilter a function of the tree alone.

    Dropping them alone would strand a tree owned by someone else, though -- a
    root-checked-out CI image, a shared mirror -- because git refuses to work in
    one unless safe.directory names it, and honours safe.directory only from
    protected configuration. So we supply it rather than defer: GIT_CONFIG_* is
    the "command" scope, which is protected (git >= 2.38), and naming one exact
    realpath is not the blanket bypass safe.directory=* would be. Appending past
    a caller's own GIT_CONFIG_COUNT leaves their entries intact.

    Getting this wrong is expensive and quiet: a git that cannot open the tree
    makes spatch print "0 files match" and exit 0, so every CVE reads as absent.
    """
    env = dict(os.environ)
    if 'OCAMLRUNPARAM' not in env and 'CAMLRUNPARAM' not in env:
        env['OCAMLRUNPARAM'] = SPATCH_OCAMLRUNPARAM
    env.setdefault('GIT_CONFIG_GLOBAL', os.devnull)
    env.setdefault('GIT_CONFIG_NOSYSTEM', '1')
    if kernel:
        try:
            count = int(env.get('GIT_CONFIG_COUNT') or 0)
        except ValueError:
            count = 0
        env[f'GIT_CONFIG_KEY_{count}'] = 'safe.directory'
        env[f'GIT_CONFIG_VALUE_{count}'] = os.path.realpath(kernel)
        env['GIT_CONFIG_COUNT'] = str(count + 1)
    return env


def check_git_prefilter(kernel: str) -> list[str]:
    """Whether git can still open the tree, when spatch is going to ask it to.

    Handed a git directory spatch prefilters with `git grep`, and a git that
    cannot open the repository exits non-zero -- which spatch reports as "0 files
    match" and exit 0. Repo discovery is the part that fails (an unreadable
    config, an ownership check), so `rev-parse` proves it without walking the
    tree. It lives here, next to the environment it has to run under, because
    that environment is the thing most likely to break it.
    """
    if not os.path.isdir(os.path.join(kernel, '.git')):
        return []
    try:
        run = subprocess.run(
            ['git', 'rev-parse', '--show-toplevel'],
            cwd=kernel,
            capture_output=True,
            text=True,
            check=False,
            env=_spatch_env(kernel),
        )
    except OSError as err:
        return [f'cannot run git in {kernel}: {err}']
    if run.returncode != 0:
        return [f'git cannot open {kernel}: {run.stderr.strip() or run.returncode}']
    return []


def _run_spatch(
    cve: str,
    kernel: str,
    cmd: list[str],
    wall_timeout: int,
    workdir: str,
    zygote: bool = False,
    demanded: bool = False,
    features: frozenset[str] = frozenset(),
) -> str:
    """Run spatch under both budgets and hand back its stdout, or raise.

    Both halves of "did this run finish" live here so they cannot be used apart:
    a caller that got the wall watchdog but skipped the engine verdict would
    read a rule that gave up as a rule that found nothing.

    With zygote=True the request goes through a per-process `spatch --zygote`
    server instead of an exec; workdir is where the request child leaves its
    stdout/stderr. Both transports come back as (returncode, stdout, stderr) or
    raise TimeoutError carrying the partial stderr as its message, so all
    classification below -- the wall half and the engine half alike -- is
    shared and the two cannot drift apart.

    demanded says the transport was asked for rather than inferred, which is
    the difference between "fall back quietly" and "fail so the user finds
    out": a mode that silently does something else cannot be tested.

    A run that dropped files is never returned. It gets at most one rerun, and
    only when truncation_retry() names a cause the rerun removes; a second
    truncation is the answer. With the transport fallback above that bounds a
    request at three invocations: a failed zygote child, the exec that replaced
    it, and that exec again without the AST cache.
    """
    env = _spatch_env(kernel)

    def attempt(argv: list[str], on_zygote: bool, degrade: bool = False) -> tuple[int, str, str]:
        # Every invocation answers to the same wall budget, and a timeout reads
        # the same on either transport: whatever spatch said before the kill is
        # the only clue to where it wedged, and both hand it over as the message.
        try:
            if on_zygote:
                return spatch_zygote.run(argv, env, workdir, wall_timeout, degrade=degrade)
            return _exec_spatch(argv, env, wall_timeout)
        except TimeoutError as err:
            raise SpatchTimeout(
                cve, kernel, -signal.SIGKILL, str(err), wall_timeout, wall=True
            ) from err

    degraded: str | None = None
    returncode, stdout, stderr = 0, '', ''
    try:
        returncode, stdout, stderr = attempt(cmd, zygote, degrade=not demanded)
    except spatch_zygote.ZygoteUnsupported as err:
        # This spatch cannot serve; it said so on its first request and will
        # not be asked again. Finish this CVE on the stock transport so the
        # scan degrades in speed rather than losing a verdict.
        degraded = f'falling back to one spatch per rule ({err})'
    except spatch_zygote.ZygoteDied as err:
        # The server died mid-request. Seen on whole-tree scans of thousands of
        # files, where the child segfaults in OCaml's unmarshaller: the same
        # scan run as a plain exec answers normally, so the request is sound and
        # only the transport failed. A transport fault must not become the
        # rule's verdict -- that is how a valid rule silently loses strong. run()
        # has already killed and reset the server, so the retry starts clean.
        # A demanded zygote still fails loudly: asking for a mode and getting
        # another one quietly is what `demanded` exists to prevent.
        if demanded:
            raise SpatchError(cve, kernel, -1, str(err)) from err
        degraded = f'zygote died, retrying without it ({err})'

    if zygote and degraded is None and returncode != 0 and not demanded:
        # A request that failed inside the server's child, with the server itself
        # healthy: nothing raised ZygoteDied and the status arrived as an
        # ordinary non-zero return, which the engine half below would read as the
        # rule's own failure. The child forks off a server that has been serving
        # all along, so it starts with that accumulated heap and meets the
        # address-space cap far sooner than a fresh process would -- on
        # whole-tree scans of thousands of files it dies (SIGSEGV in OCaml's
        # unmarshaller, or an uncaught Out_of_memory) where one exec of the same
        # rule over the same tree answers in half a minute. So the verdict is
        # retried once on the stock transport, with its own clean budget, and
        # only a second failure is the rule's. A demanded zygote still reports
        # the failure as it stands.
        degraded = f'zygote request failed (rc {returncode}), retrying without it'

    if degraded is not None:
        log.warning('%s: %s', cve, degraded)
        returncode, stdout, stderr = attempt(cmd, False)

    dropped = _engine_verdict(cve, kernel, cmd, returncode, stderr, features)
    if dropped is None:
        return stdout

    truncated = _truncated(cve, kernel, returncode, stderr, dropped)
    via_zygote = zygote and degraded is None
    retry = truncation_retry(cmd, dropped, via_zygote, demanded)
    if retry is None:
        raise truncated
    prefix, retry_zygote = retry
    retry_cmd, how = cmd, []
    if prefix is not None:
        astcache_evict(prefix, [file for _exn, file in dropped])
        retry_cmd = _without_cache_prefix(cmd)
        how.append('without the AST cache')
    if via_zygote and not retry_zygote:
        how.append('as one exec')
    log.warning(
        '%s: spatch dropped %s mid-scan (%s); retrying %s',
        cve,
        ', '.join(truncated.files) or 'unnamed files',
        ', '.join(truncated.kinds) or 'no exception named',
        ' and '.join(how),
    )
    try:
        returncode, stdout, stderr = attempt(retry_cmd, retry_zygote)
    except spatch_zygote.ZygoteDied as err:
        # Only a demanded zygote retries on the zygote, and it fails loudly.
        raise SpatchError(cve, kernel, -1, str(err)) from err
    dropped = _engine_verdict(cve, kernel, retry_cmd, returncode, stderr, features)
    if dropped is not None:
        raise _truncated(cve, kernel, returncode, stderr, dropped, retried=True)
    return stdout


def _engine_verdict(
    cve: str,
    kernel: str,
    cmd: list[str],
    returncode: int,
    stderr: str,
    features: frozenset[str],
) -> list[tuple[str, str]] | None:
    """The engine half: raise for a timeout or a failed run, else the files a
    run dropped -- None when it scanned everything it was given.

    A question the classifiers answer from stderr plus the exit code: handed a
    directory, spatch drops the file it gave up on and still exits 0, so neither
    alone would do. A timeout is checked first because it is the rule's fault and
    takes the same shape; any other dropped file is the environment's, and is
    returned rather than raised so the caller can decide on one rerun. Returning
    stdout for it would answer "not vulnerable" for a file never looked at, and a
    caller's cache would keep that.

    Handed files by name, spatch instead dies on the first exception without
    naming the file. When that exception is a cache fault, the run comes back as
    a drop of every source the command named, so the caller evicts their entries
    and reruns once without the cache; otherwise, and always without a cache on
    the command line, a non-zero exit is the engine's failure.
    """
    timed_out = parse_spatch_timeout(stderr, returncode)
    if timed_out is not None:
        raise SpatchTimeout(
            cve,
            kernel,
            returncode,
            stderr,
            SPATCH_TIMEOUT,
            [os.path.relpath(f, kernel) for f in timed_out],
        )
    if returncode == 0:
        if 'summary' not in features:
            return parse_spatch_truncation(stderr)
        # A build that ends every scan with a summary has said whether it
        # finished, so its absence is the answer "it did not" -- the shape an
        # empty stdout cannot distinguish from a clean tree (a child that
        # exited 0 without scanning, a capture cut short).
        counts = parse_spatch_summary(stderr)
        if counts is None:
            log.warning('%s: spatch printed no SPATCH-SUMMARY; the scan did not finish', cve)
            return []
        if counts.get('dropped') or counts.get('unreadable'):
            return parse_spatch_drops(stderr) or parse_spatch_truncation(stderr) or []
        return None
    if '--cache-prefix' in cmd:
        sources = _cmd_sources(cmd)
        lost = [(exn, file) for exn in parse_spatch_fatal(stderr) for file in sources]
        if is_cache_fault(lost):
            return lost
    raise SpatchError(cve, kernel, returncode, stderr)


def _truncated(
    cve: str,
    kernel: str,
    returncode: int,
    stderr: str,
    dropped: list[tuple[str, str]],
    retried: bool = False,
) -> SpatchTruncated:
    relative = [(exn, os.path.relpath(file, kernel)) for exn, file in dropped]
    return SpatchTruncated(cve, kernel, returncode, stderr, relative, retried)


def truncation_retry(
    cmd: list[str], dropped: list[tuple[str, str]], via_zygote: bool, demanded: bool
) -> tuple[str | None, bool] | None:
    """The one rerun a scan that dropped files gets, or None: (the AST cache to
    evict the dropped files from and rerun without, or None to keep it; whether
    the rerun goes on the zygote).

    Two causes are worth a second run, because the rerun removes each:

    - the AST cache. A torn or short entry raises in coccinelle's reader, which
      neither re-parses nor evicts it, so every scan sharing the cache would drop
      the file again. The caller evicts the named entries and the rerun goes
      without --cache-prefix; the cache holds parses, never verdicts, so the
      answer cannot differ.
    - the transport. An inferred zygote's child starts on the server's long-lived
      heap, so it is rerun as one exec on a fresh budget, as a failed child is.

    Anything else -- an exec that lost a file to Out_of_memory, a parse that
    fails outright -- would fail the same way twice, and is the answer. A
    demanded zygote keeps its transport: asking for it and quietly getting an
    exec is what `demanded` exists to prevent.
    """
    prefix = _cache_prefix(cmd) if is_cache_fault(dropped) else None
    transport_fault = via_zygote and not demanded
    if prefix is None and not transport_fault:
        return None
    return prefix, via_zygote and demanded


def _cache_prefix(cmd: list[str]) -> str | None:
    try:
        return cmd[cmd.index('--cache-prefix') + 1]
    except (ValueError, IndexError):
        return None


def _without_cache_prefix(cmd: list[str]) -> list[str]:
    at = cmd.index('--cache-prefix')
    return cmd[:at] + cmd[at + 2 :]


def _cmd_sources(cmd: list[str]) -> list[str]:
    """The sources a check_cve command line names: the operands after the rule,
    then each --include, which spatch parses and caches the same way."""
    sources = cmd[cmd.index('--cocci-file') + 2 :] if '--cocci-file' in cmd else []
    return sources + [cmd[at + 1] for at, arg in enumerate(cmd[:-1]) if arg == '--include']


def _exec_spatch(cmd: list[str], env: dict[str, str], wall_timeout: int) -> tuple[int, str, str]:
    """The stock transport: one spatch exec per request, killed as one group.

    The wall half needs its own process group. subprocess.run(timeout=) kills
    only spatch, leaving the parmap workers it forks under -j>1 orphaned and
    still burning cores; start_new_session lets one signal reach all of them.
    That also costs spatch its SIGINT, so the same kill runs for any exception.
    """
    with subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        # spatch echoes bytes from the files it scanned, and the kernel holds
        # sources that are not UTF-8 (CVE-2018-16276's fixes tree: 0xa5 at the
        # top of a hunk)
        errors='replace',
        start_new_session=True,
        env=env,
    ) as proc:
        try:
            # 0 disables the watchdog, matching what spatch reads --timeout 0 as.
            stdout, stderr = proc.communicate(timeout=wall_timeout or None)
        except subprocess.TimeoutExpired as err:
            killpg(proc.pid)
            # communicate() leaves the partial stderr out of its exception, so
            # carry it out as the TimeoutError message instead.
            raise TimeoutError(proc.communicate()[1]) from err
        except BaseException:
            killpg(proc.pid)
            proc.communicate()
            raise
    return proc.returncode, stdout, stderr


def relative_to(root: str, path: str) -> str:
    """A path under root, named the way the tree names it.

    Findings are reported per tree, and under --rev or diff that tree is a
    temporary directory that stops existing when the run ends -- an absolute
    path there points nowhere and leaks the blob store's layout. Anything not
    under root is left alone.
    """
    if path == root:
        return '.'
    prefix = root.rstrip(os.sep) + os.sep
    return path[len(prefix) :] if path.startswith(prefix) else path


def parse_rule_header(path: str) -> RuleMetadata:
    """The leading `///` block of a rule: Files:, Fix:, Fixes:/Detect-To:, Version:.

    Module-level rather than a method because the CLI needs every rule's Files:
    before it has a CVEhound to ask -- under `scan --rev` the tree those files
    are read from does not exist until they are known.
    """
    files: list[str] = []
    fix: str | None = None
    fixes: str | None = None
    version: int | str = 0

    with open(path) as fh:
        for line in fh:
            if not line.startswith('///'):
                break
            if 'Files:' in line:
                files = line.partition('Files:')[2].split()
            elif 'Fix:' in line:
                fix = line.partition('Fix:')[2].strip()
            elif 'Fixes:' in line:
                fixes = line.partition('Fixes:')[2].strip()
            elif 'Detect-To:' in line:
                fixes = line.partition('Detect-To:')[2].strip()
            elif 'Version:' in line:
                version = line.partition('Version:')[2].strip()
                try:
                    version = int(version.replace('.', ''))
                except ValueError:
                    # An unparsable requirement must degrade to "run the
                    # rule" (prefer a false positive), not abort the scan.
                    logging.warning(
                        '%s: cannot parse Version: %r; ignoring the spatch requirement',
                        os.path.basename(path),
                        version,
                    )
                    version = 0

    return {'files': files, 'fix': fix, 'fixes': fixes, 'version': version}


class CVEhound:
    def __init__(
        self,
        kernel: str,
        metadata: str | None = None,
        config: str | None = None,
        check_strict: bool = False,
        arch: str = 'x86',
        spatch: str | None = None,
        zygote: str | None = None,
        ast_cache: str | None = None,
    ) -> None:
        kernel = os.path.abspath(kernel)
        self.kernel = kernel
        self.metadata: dict[str, Any] = get_cves_metadata(metadata)
        self.spatch: str = spatch or find_spatch()
        self.spatch_version = get_spatch_version(self.spatch)
        # spatch renders its context-mode output by shelling out to diff(1),
        # and without it prints an internal error and still exits 0 -- so an
        # unnoticed missing diffutils turns every rule into a silent miss.
        if shutil.which('diff') is None:
            raise SpatchNotFound('diff not found: spatch needs diffutils to report what it matched')
        self.check_strict = check_strict
        # Both transport knobs are resolved here rather than at the point of
        # use, so that a library caller and the test suite -- neither of which
        # goes through __main__ -- get the same decision the CLI does, and so
        # the sandbox grant and the --cache-prefix argument cannot disagree
        # about the cache directory.
        self.zygote_mode = zygote = zygote or 'auto'
        self.zygote = resolve_zygote(zygote, self.spatch)
        # What the binary guarantees beyond stock spatch, such as whether a scan
        # must end with a summary.
        self.features = spatch_features(self.spatch)
        if ast_cache is None:
            ast_cache = os.environ.get('CVEHOUND_SPATCH_ASTCACHE')
        self.astcache = astcache_dir(ast_cache, self.spatch)
        self.arch = arch
        self.srcarch = get_srcarch(arch)
        self.rules_metadata: dict[str, RuleMetadata] = {}
        (self.cve_all_rules, self.cve_assigned_rules, self.cve_disputed_rules) = get_rule_cves()

        self.ipaths = [
            os.path.join('arch', self.srcarch, 'include'),
            os.path.join('arch', self.srcarch, 'include/generated'),
            os.path.join('arch', self.srcarch, 'include/uapi'),
            os.path.join('arch', self.srcarch, 'include/generated/uapi'),
            'include',
            'include/uapi',
            'include/generated/uapi',
        ]

        self.config_file: str | None = None
        self.config_map: dict[str, str] | None = None
        self.config: Config | None = None

        if config:
            self.config_map = KbuildParser(None, arch, kernel).parse_tree()
            if not self.config_map:
                logging.warning(
                    "Couldn't map any kernel file to CONFIG_ options: "
                    'every finding will be reported as affected'
                )
            if config != '-':
                self.config_file = config
                self.config = Config(config)

        if self.spatch_version < 110:
            logging.warning(
                'spatch (coccinelle) versions older than 1.1.0 are not supported.\n'
                'Please, update to coccinelle >= 1.1.0.'
            )

    def get_grep_pattern(self, rule: str) -> list[str]:
        patterns: list[str] = []
        with open(rule) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('//'):
                    continue
                patterns.append(line)
        return patterns

    def _print_found_cve(self, cve: str) -> None:
        logging.warning('Found: ' + cve)
        if cve in self.metadata:
            info = self.metadata[cve]
            if 'cmt_msg' in info:
                logging.info('MSG: ' + info['cmt_msg'])
            if 'fix_date' in info:
                logging.info('FIX DATE: ' + fix_date_str(info['fix_date']))
        logging.info('https://www.cve.org/CVERecord?id=' + cve)

    def _print_affected_files(self, config: dict[str, Any]) -> None:
        if 'files' in config and config['files']:
            logging.info('Affected Files:')
            for file in config['files']:
                entry = config['files'][file]
                logic = entry['logic']
                verdict = entry.get('config')
                if verdict is not None and self.config_file:
                    affected = 'affected' if verdict else 'not affected'
                    logging.info(
                        ' - ' + file + ': ' + logic + '\n   ' + self.config_file + ': ' + affected
                    )
                else:
                    logging.info(' - ' + file + ': ' + logic)

        if 'affected' not in config or config['affected'] is None:
            return
        config_affected = 'affected' if config['affected'] else 'not affected'
        if self.config is not None and self.config_file:
            logging.info('Config: ' + self.config_file + ' ' + config_affected)
        else:
            logging.info('Config: any ' + config_affected)

    def check_cve(self, cve: str, all_files: bool = False, jobs: int = 1) -> dict[str, Any] | bool:
        result: dict[str, Any] = {}
        is_grep = False
        rule = self.cve_all_rules[cve]
        if rule.endswith('.grep'):
            is_grep = True

        if all_files:
            files = [self.kernel]
        else:
            rule_files = self.get_rule_files(cve)
            files = [
                os.path.join(self.kernel, f)
                for f in rule_files
                if os.path.exists(os.path.join(self.kernel, f))
            ]
            if not files:
                logging.debug('Skipping %s: none of the hinted files exist', cve)
                return False

        # Built from self.kernel per call so a shallow copy pointed at another
        # tree (cvehound.oracle.kerneltree hound_at) needs no include rewriting.
        includes: list[str] = []
        for ipath in self.ipaths:
            includes.append('-I')
            includes.append(os.path.join(self.kernel, ipath))
        kconfig = os.path.join(self.kernel, KCONFIG_H)
        if os.path.exists(kconfig):
            includes.append('--include')
            includes.append(kconfig)

        logging.debug('Checking: ' + cve)

        output = ''
        hits: list[dict[str, str | int]] = []
        if not is_grep:
            rule_ver = self.get_rule_version(cve)
            if rule_ver and rule_ver > self.spatch_version:
                raise UnsupportedVersion(self.spatch_version, cve, rule_ver)
            # spatch stages each parmap worker's output in a directory built from
            # --tmp-dir and removes it as it exits (enter.ml, par_fold) -- which
            # the watchdog's SIGKILL denies it. A private directory keeps the
            # strand ours to remove, and keeps the staging out of a world-writable
            # /tmp, where a predictable name is at least a denial of service
            # (spatch refuses to start when the path exists) and, under a
            # permissive umask, lets a planted stdout* file be replayed as hits.
            with tempfile.TemporaryDirectory(
                prefix='cvehound-spatch-', ignore_cleanup_errors=True
            ) as tmpdir:
                # Experimental: share parsed-C ASTs between rules that target
                # the same file (they are rule-independent under our flag set).
                cocci_cmd = [
                    self.spatch,
                    *(['--cache-prefix', self.astcache] if self.astcache else []),
                    '--no-includes',
                    '--include-headers',
                    '--chunksize',
                    '1',
                    '-j',
                    str(jobs),
                    '--timeout',
                    str(SPATCH_TIMEOUT),
                    '--tmp-dir',
                    os.path.join(tmpdir, 'par'),
                    '--very-quiet',
                    *includes,
                    '--cocci-file',
                    rule,
                    *files,
                ]

                logging.debug(' '.join(cocci_cmd))

                output = _run_spatch(
                    cve,
                    self.kernel,
                    cocci_cmd,
                    SPATCH_WALL_TIMEOUT,
                    workdir=tmpdir,
                    zygote=self.zygote,
                    demanded=self.zygote_mode == 'on',
                    features=self.features,
                ).strip()
            # Rules report by starring lines: a match is a unified diff of the
            # starred lines on stdout, silence means not vulnerable. The parsed
            # hits are the verdict, so "detected" and the reported locations can
            # never disagree.
            hits = parse_coccinelle_output(output)
            if not hits:
                return False
        else:
            # Resolved once, before the loop: a grep without -P cannot answer
            # any of these patterns, and finding that out per pattern would
            # report it as a property of the first one.
            grep = pcre_grep()
            for pattern in self.get_grep_pattern(rule):
                args = [grep, '-rPzle', pattern, *files]
                run = subprocess.run(args, capture_output=True, check=False, text=True)
                if run.returncode != 0:
                    # A grep rule needs every pattern to match somewhere.
                    return False
                output += run.stdout.strip()

        config_result: dict[str, Any] = {}
        if self.config_map is not None:
            kernel_files: dict[str, str | None] = {}
            file_list: list[str] = []
            if not is_grep:
                file_list = sorted({str(hit['file']) for hit in hits})
            else:
                for line in output.split('\n'):
                    while True:
                        try:
                            rindex = line.rindex(self.kernel)
                        except ValueError:
                            break
                        file_list.append(line[rindex:])
                        line = line[:rindex]
            for f in file_list:
                if os.path.isfile(f):
                    kernel_files[f] = self.config_map.get(f)
            if kernel_files:
                verdicts: list[bool] = []
                config_result['files'] = {}
                for kfile, kconfig in kernel_files.items():
                    rel_file = relative_to(self.kernel, kfile)
                    logic, affected = evaluate_file_condition(
                        kconfig, rel_file, self.srcarch, self.config
                    )
                    result_file: dict[str, Any] = {
                        'logic': logic,
                        'mapped': kconfig is not None,
                    }
                    if logic == 'unknown':
                        # Only compilation units are expected in the map;
                        # headers and the like are never built on their own.
                        report = (
                            logging.warning
                            if rel_file.endswith(COMPILED_SUFFIXES)
                            else logging.debug
                        )
                        report('No Kbuild mapping for ' + rel_file + ': assuming the file is built')
                    if affected is not None:
                        result_file['config'] = affected
                        verdicts.append(affected)
                    config_result['files'][rel_file] = result_file
                if verdicts:
                    config_result['affected'] = any(verdicts)

        # Drop a hit under --check-strict only when the .config evaluation
        # explicitly ruled every affected file out; an undetermined verdict
        # (no .config, unmapped files) must not silence a finding.
        if self.check_strict and config_result.get('affected') is False:
            return False

        if cve in self.metadata:
            result = self.metadata[cve]
        result['config'] = config_result
        # Relative from here on: the config block above needs the absolute
        # paths its config_map is keyed by, and everything reported after it
        # names files the way the scanned tree does.
        result['spatch_output'] = output.replace(self.kernel + os.sep, '')
        if not is_grep:
            result['files'] = [
                dict(hit, file=relative_to(self.kernel, str(hit['file']))) for hit in hits
            ]
        else:
            result['files'] = [{'file': relative_to(self.kernel, f)} for f in files]
        self._print_found_cve(cve)
        self._print_affected_files(config_result)
        logging.debug(output)
        logging.info('')

        return result

    def get_rule_metadata(self, cve: str) -> RuleMetadata:
        if cve not in self.rules_metadata:
            self.rules_metadata[cve] = parse_rule_header(self.cve_all_rules[cve])
        return self.rules_metadata[cve]

    def get_cve_metadata(self, cve: str) -> dict[str, Any]:
        result: dict[str, Any] = self.metadata.get(cve, {})
        return result

    def get_cve_exploit(self, cve: str) -> bool:
        exploit: bool = self.get_cve_metadata(cve).get('exploit', False)
        return exploit

    def get_all_cves(self) -> set[str]:
        return set(self.cve_all_rules.keys())

    def get_assigned_cves(self) -> set[str]:
        return set(self.cve_assigned_rules.keys())

    def get_disputed_cves(self) -> set[str]:
        return set(self.cve_disputed_rules.keys())

    def get_rule(self, cve: str) -> str:
        return self.cve_all_rules[cve]

    def add_rule(self, cve: str, path: str) -> None:
        """Register (or replace) a rule file outside the resolved content set.

        For scoring candidate rules that are not part of the shipped content —
        e.g. a generation harness checking a rule it just wrote. The cached
        header metadata for the CVE is dropped, so re-registering the same CVE
        with a different file is safe. Prefer a fresh path per candidate over
        rewriting one in place: cvehound.oracle.ResultCache memoizes rule bytes
        by path behind a (mtime_ns, size) guard, so an in-place rewrite is
        detected, but only as precisely as the filesystem stat is. The
        assigned/disputed group views are content-set bookkeeping and
        deliberately stay untouched.

        hound_at() copies share these dicts, so a rule added on the base hound
        is visible to every copy — one registration covers all trees.
        """
        self.cve_all_rules[cve] = os.path.abspath(path)
        self.rules_metadata.pop(cve, None)

    def get_rule_fix(self, cve: str) -> str | None:
        fix: str | None = self.get_rule_metadata(cve)['fix']
        return fix

    def get_rule_fixes(self, cve: str) -> str | None:
        fixes: str | None = self.get_rule_metadata(cve)['fixes']
        return fixes

    def get_rule_files(self, cve: str) -> list[str]:
        files: list[str] = self.get_rule_metadata(cve)['files']
        return files

    def get_rule_version(self, cve: str) -> int:
        version: int = self.get_rule_metadata(cve)['version']
        return version
