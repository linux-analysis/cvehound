"""The stages every subcommand shares: settings, hound, CVE selection, report, pool.

Lifted out of the historical monolithic main() so that `scan`, `diff` and
`bisect` build the same CVEhound from the same settings and fan work out over
the same pool. Anything that exits the process on a bad input does so here
with the message the historical CLI printed.
"""

import argparse
import concurrent.futures
import contextlib
import json
import logging
import multiprocessing
import os
import re
import sys
import zlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, NoReturn

from cvehound import SPATCH_TIMEOUT, SPATCH_WALL_TIMEOUT, CVEhound
from cvehound.content import resolve_content
from cvehound.exception import (
    PcreGrepNotFound,
    SandboxError,
    SpatchError,
    SpatchNotFound,
    SpatchTimeout,
    SpatchTruncated,
    UnsupportedVersion,
)
from cvehound.gitrepo import GitRepo
from cvehound.sandbox import install as install_sandbox
from cvehound.util import (
    astcache_prune,
    find_spatch,
    fix_date_str,
    get_cvehound_version,
    get_cves_metadata,
    get_rule_cves,
    get_srcarch,
    latest_fix_date,
    parse_config,
    resolve_metadata_path,
)
from cvehound.worker import _worker_check_cve, _worker_init, setup_logging

SANDBOX_MODES = ('auto', 'off', 'strict')
ZYGOTE_MODES = ('auto', 'off', 'on')

# What the AST cache is allowed to grow to before a scan evicts its
# least-recently-used entries. A targeted scan of one kernel tree measures
# ~310MB, so this holds a few trees; coccinelle never prunes anything itself.
ASTCACHE_LIMIT = 4 * 1024 * 1024 * 1024

# Metadata older than this gets a warning; --exploit is stricter because the
# CISA KEV catalog it filters on changes much faster than the fix data.
METADATA_STALE_DAYS = 90
METADATA_STALE_DAYS_EXPLOIT = 30

CVE_ID = re.compile(r'^CVE-\d{4}-\d{4,7}$')
CVE_GROUPS = ('all', 'assigned', 'disputed')

# One unit of pool work: which rule, whole-tree or hinted files, and the
# directory to run it in (None: the hound's own tree).
Task = tuple[str, bool, str | None]


def fail(*message: object) -> NoReturn:
    print(*message, file=sys.stderr)
    sys.exit(1)


def format_version_info() -> str:
    """Tool version plus the identity of the content it would scan with."""
    lines = ['cvehound ' + get_cvehound_version()]
    content = resolve_content()
    (all_rules, _, _) = get_rule_cves()
    origin = content.source
    if content.content_id:
        origin += ' ' + content.content_id
    if content.source_commit:
        origin += ', commit ' + content.source_commit[:12]
    lines.append(f'rules: {len(all_rules)} ({origin})')
    try:
        path = resolve_metadata_path(None)
    except (FileNotFoundError, ValueError) as err:
        lines.append(f'metadata: error: {err}')
        return '\n'.join(lines)
    if path is None:
        lines.append("metadata: none (run 'cvehound update')")
    elif path == content.metadata_path and content.metadata_generated:
        # The verified manifest already carries the blob's generation date:
        # no need to gunzip and parse the whole blob just for --version.
        lines.append(f'metadata: updated {content.metadata_generated} ({path})')
    else:
        try:
            metadata = get_cves_metadata(path)
        except (OSError, EOFError, ValueError, zlib.error) as err:
            # A corrupt or truncated blob must not crash the very command
            # users run to diagnose their install.
            lines.append(f'metadata: error: {path}: {err}')
            return '\n'.join(lines)
        latest = latest_fix_date(metadata)
        if latest:
            lines.append(f'metadata: updated {fix_date_str(latest)} ({path})')
        else:
            lines.append(f'metadata: {path}')
    return '\n'.join(lines)


class _VersionAction(argparse.Action):
    def __init__(self, option_strings: list[str], dest: str, **kwargs: Any) -> None:
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        print(format_version_info())
        parser.exit()


def common_parser() -> argparse.ArgumentParser:
    """The options every subcommand takes, as an argparse parent.

    A parent rather than a shared parser so that each subcommand's own
    get_default() sees these actions: the cvehound.ini merge in load_settings()
    asks it which values the user actually typed.
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        '--config',
        metavar='FILE',
        help='cvehound.ini config file (default: /etc/cvehound.ini or $HOME/.config/cvehound.ini',
    )
    parser.add_argument('--kernel', '-k', metavar='DIR', help='linux kernel sources dir')
    parser.add_argument(
        '-v', '--verbose', action='count', default=0, help='increase output verbosity'
    )
    parser.add_argument(
        '--exploit', '-e', action='store_true', help='check only for CVEs with exploits'
    )
    parser.add_argument(
        '--report', nargs='?', const='report.json', help='output report with found CVEs'
    )
    parser.add_argument(
        '--metadata', metavar='PATH', help='Path to non-standard location of kernel_cves.json.gz'
    )
    parser.add_argument(
        '--spatch',
        metavar='PATH',
        help='spatch binary to use (default: $CVEHOUND_SPATCH, the bundled'
        ' cvehound-spatch package, then PATH)',
    )
    parser.add_argument(
        '--sandbox',
        choices=SANDBOX_MODES,
        default=os.environ.get('CVEHOUND_SANDBOX', 'auto'),
        help='confine the scan with landlock and seccomp: auto falls back to an'
        ' unconfined scan when the kernel cannot do it, strict refuses to scan'
        ' (default: $CVEHOUND_SANDBOX, else auto)',
    )
    parser.add_argument(
        '--zygote',
        choices=ZYGOTE_MODES,
        default='auto',
        help='run spatch as one warm server per worker instead of one process'
        ' per rule: auto uses it when the installed cvehound-spatch supports it'
        ' (default: auto)',
    )
    parser.add_argument(
        '--version',
        action=_VersionAction,
        default=argparse.SUPPRESS,
        help='show the tool, rules, and metadata versions and exit',
    )
    return parser


def add_cve_options(parser: argparse.ArgumentParser, greedy: bool) -> None:
    """--cve and --exclude, in one of two shapes.

    Greedy (`--cve A B C`) is the historical scan spelling. A subcommand with a
    positional takes them repeatable instead (`--cve A --cve B`): a greedy list
    would swallow the A..B that follows it. select_cves() reads both the same.
    """
    groups = ', '.join(CVE_GROUPS)
    if greedy:
        parser.add_argument(
            '--cve',
            '-c',
            nargs='+',
            default=['assigned'],
            help=f'list of cve identifiers (groups: [{groups}])',
        )
        parser.add_argument(
            '--exclude',
            '-x',
            nargs='+',
            default=[],
            metavar='CVE',
            help='list of cve identifiers or a file with them to exclude CVEs from check',
        )
    else:
        parser.add_argument(
            '--cve',
            '-c',
            action='append',
            metavar='CVE',
            help=f'a cve identifier or group ({groups}), repeatable (default: assigned)',
        )
        parser.add_argument(
            '--exclude',
            '-x',
            action='append',
            metavar='CVE',
            help='a cve identifier or a file with them to exclude, repeatable',
        )


def check_config(config: dict[str, Any]) -> None:
    valid_config_options = {
        'kernel',
        'cve',
        'exclude',
        'exploit',
        'verbose',
        'files',
        'ignore_files',
        'kernel_config',
        'check_strict',
        'report',
        'all_files',
        'metadata',
        'arch',
        'spatch',
        'sandbox',
        'zygote',
        'cache',
        'cache_clear',
    }
    diff = set(config.keys()) - valid_config_options
    if diff:
        fail('Unknown config options: ' + ','.join(diff))


def load_settings(parser: argparse.ArgumentParser, cmdargs: argparse.Namespace) -> dict[str, Any]:
    """cvehound.ini defaults under the command line: a typed option wins, a
    default yields to the file. Only keys this subcommand knows are taken from
    the file, so a `files =` line meant for scan does not steer diff."""
    config_args: dict[str, Any] = {}
    try:
        if cmdargs.config:
            config_args = parse_config(cmdargs.config)
        else:
            if os.path.isfile('/etc/cvehound.ini'):
                config_args = parse_config('/etc/cvehound.ini')
            if 'HOME' in os.environ:
                home_config_path = os.path.join(os.environ['HOME'], '.config', 'cvehound.ini')
                if os.path.isfile(home_config_path):
                    config_args.update(parse_config(home_config_path))
    except Exception as err:
        fail("Can't parse config file:", err)
    check_config(config_args)
    cmdargs_dict = vars(cmdargs)
    merged_args: dict[str, Any] = {k: v for k, v in config_args.items() if k in cmdargs_dict}
    for arg in cmdargs_dict:
        if cmdargs_dict[arg] != parser.get_default(arg) or arg not in merged_args:
            merged_args[arg] = cmdargs_dict[arg]

    # argparse checks `choices` only for a value it parsed off the command line:
    # $CVEHOUND_SANDBOX supplies the default and cvehound.ini overrides it, so
    # neither is validated. Untreated, 'Off' or 'no' would read as "not off" and
    # confine a scan the user asked to leave alone.
    for name, modes in (('sandbox', SANDBOX_MODES), ('zygote', ZYGOTE_MODES)):
        if merged_args[name] not in modes:
            fail(
                f'Wrong --{name} value:',
                merged_args[name] + ' (expected ' + ', '.join(modes) + ')',
            )
    return merged_args


def require_kernel(parser: argparse.ArgumentParser, args_cfg: dict[str, Any]) -> str:
    if not args_cfg['kernel']:
        parser.print_usage()
        fail(f'{parser.prog}: error: the following arguments are required: --kernel/-k')
    return args_cfg['kernel']


def resolve_metadata(args_cfg: dict[str, Any]) -> str | None:
    try:
        # Also validates $CVEHOUND_METADATA, which --metadata's checks never saw.
        return resolve_metadata_path(args_cfg['metadata'])
    except (FileNotFoundError, ValueError) as err:
        fail(err)


def resolve_spatch(args_cfg: dict[str, Any]) -> str:
    try:
        return find_spatch(args_cfg.get('spatch'))
    except SpatchNotFound as err:
        fail(err)


def check_metadata_freshness(metadata: dict[str, Any], exploit: bool) -> None:
    if not metadata:
        if exploit:
            fail(
                '--exploit needs CVE metadata, but none was found; '
                "run 'cvehound update' to fetch it"
            )
        print(
            'Warning: no CVE metadata found, findings will lack commit details; '
            "run 'cvehound update' to fetch it",
            file=sys.stderr,
        )
        return
    latest = latest_fix_date(metadata)
    if not latest:
        return
    age_days = int((datetime.now(tz=UTC).timestamp() - latest) // 86400)
    limit = METADATA_STALE_DAYS_EXPLOIT if exploit else METADATA_STALE_DAYS
    if age_days > limit:
        hint = ' (--exploit may miss recently catalogued exploits)' if exploit else ''
        print(
            f'Warning: the CVE metadata is ~{age_days} days old{hint}; '
            "run 'cvehound update' to refresh it",
            file=sys.stderr,
        )


def ensure_rules(all_rules: dict[str, str]) -> None:
    """An empty rule set means a broken install (e.g. an interrupted run of the
    legacy in-place updater); scanning would silently report nothing."""
    if all_rules:
        return
    content = resolve_content()
    if content.source == 'overlay':
        remedy = "run 'cvehound update --force' to reinstall the content overlay"
    else:
        remedy = 'reinstall the package: pip install --force-reinstall cvehound'
    fail('No detection rules found in', content.rules_dir + ';', remedy)


def resolve_arch(args_cfg: dict[str, Any], config_info: dict[str, str], kernel: str) -> str:
    """Determine the kernel architecture: --arch, else the .config banner,
    else a warned-about x86 guess. `kernel` is the tree whose arch/ is probed,
    which under --rev is the materialized one rather than --kernel."""
    arch = args_cfg.get('arch')
    config_arch = config_info.get('arch')

    if arch and config_arch and get_srcarch(arch) != get_srcarch(config_arch):
        fail(
            '--arch',
            arch,
            'conflicts with',
            args_cfg['kernel_config'],
            'generated for',
            config_arch,
        )

    arch = arch or config_arch
    if arch:
        if not os.path.isdir(os.path.join(kernel, 'arch', get_srcarch(arch))):
            fail('Unknown kernel architecture:', arch)
        return arch

    if args_cfg.get('check_strict'):
        # A guessed architecture would silently drop every arch/<real>/ CVE
        # as "not affected"; refuse to guess when dropping is enabled.
        fail(
            "--check-strict can't infer the kernel architecture from",
            args_cfg['kernel_config'],
            '(no config banner); pass --arch',
        )
    if args_cfg.get('kernel_config'):
        print('Assuming x86 kernel architecture; pass --arch to override', file=sys.stderr)
    if not os.path.isdir(os.path.join(kernel, 'arch', 'x86')):
        # Only a guess: without it the scan still works, it merely loses the
        # arch-specific include paths.
        print(
            'No arch/x86 directory in',
            kernel + '; continuing without arch-specific include paths',
            file=sys.stderr,
        )
    return 'x86'


def new_hound(
    kernel: str, args_cfg: dict[str, Any], metadata_path: str | None, spatch: str
) -> CVEhound:
    """A scanner for one tree from the settings; args_cfg['arch'] is resolved
    by then (resolve_arch)."""
    return CVEhound(
        kernel,
        metadata_path,
        args_cfg.get('kernel_config'),
        bool(args_cfg.get('check_strict')),
        args_cfg['arch'],
        spatch=spatch,
        zygote=args_cfg['zygote'],
        ast_cache=args_cfg.get('cache'),
    )


def build_hound(
    kernel: str, args_cfg: dict[str, Any], metadata_path: str | None, spatch: str
) -> CVEhound:
    """The run's first scanner, with the checks that used to follow its
    construction: an AST cache kept under its limit, a non-empty rule set,
    metadata fresh enough to trust."""
    hound = new_hound(kernel, args_cfg, metadata_path, spatch)
    if hound.astcache:
        # Coccinelle never prunes, so a cache left to itself grows without
        # bound. Evicting before the scan means the limit is what the user
        # keeps, not what they had before this run added to it.
        freed = astcache_prune(hound.astcache, ASTCACHE_LIMIT)
        if freed:
            logging.info('AST cache: evicted %.1f MB', freed / 1e6)
    ensure_rules(hound.cve_all_rules)
    check_metadata_freshness(hound.metadata, args_cfg['exploit'])
    return hound


def normalize_cve(cve: str, where: str = '') -> str:
    if not cve.startswith('CVE-'):
        cve = 'CVE-' + cve
    if not CVE_ID.match(cve):
        fail('Wrong CVE-ID:', cve, *([where] if where else []))
    return cve


def split_range(spec: str) -> tuple[str, str]:
    """A..B into its two revisions, or exit: two dots exactly (A...B is a
    different range to git, and never what a scan of two ends means)."""
    if '..' not in spec or '...' in spec:
        fail('the range must be two revisions separated by two dots: A..B')
    a, b = spec.split('..', 1)
    return a, b


def rule_touches(rule_files: Iterable[str], prefixes: list[str]) -> bool:
    """The --files filter: whether any of a rule's Files: falls under any of the
    given paths -- prefix matching, so a directory selects everything below it."""
    return any(rulefile.startswith(x) for rulefile in rule_files for x in prefixes)


def select_cves(hound: CVEhound, args_cfg: dict[str, Any]) -> list[str]:
    """The sorted CVE list a run checks, after every filter the settings carry.

    Mutates args_cfg in place the way the historical CLI did: CVE ids are
    normalized, --exclude files are expanded, path filters sorted -- the report
    records the settings as applied, not as typed.
    """
    # Repeatable options (add_cve_options greedy=False) leave None when unused.
    args_cfg['cve'] = list(args_cfg.get('cve') or ['assigned'])
    args_cfg['exclude'] = list(args_cfg.get('exclude') or [])
    cve_set: set[str]
    if args_cfg['cve'] == ['all']:
        cve_set = hound.get_all_cves()
    elif args_cfg['cve'] == ['assigned']:
        cve_set = hound.get_assigned_cves()
    elif args_cfg['cve'] == ['disputed']:
        cve_set = hound.get_disputed_cves()
    else:
        known_cves = hound.get_all_cves()
        for i, cve in enumerate(args_cfg['cve']):
            cve = normalize_cve(cve)
            args_cfg['cve'][i] = cve
            if cve not in known_cves:
                fail('Unknown CVE:', cve)
        cve_set = set(args_cfg['cve'])

    for file in args_cfg['exclude'][:]:
        if os.path.exists(file):
            args_cfg['exclude'].remove(file)
            with open(file, encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if line == '' or line.startswith('#'):
                        continue
                    args_cfg['exclude'].append(normalize_cve(line, 'in file ' + file))

    for i, cve in enumerate(args_cfg['exclude']):
        args_cfg['exclude'][i] = normalize_cve(cve)

    files = args_cfg.get('files') or []
    ignore_files = args_cfg.get('ignore_files') or []
    if args_cfg.get('all_files') and files:
        fail('--files filter and --all-files are not compatible')
    if args_cfg.get('all_files') and ignore_files:
        fail('--ignore-files filter and --all-files are not compatible')
    path_pattern = re.compile(r'^[_a-zA-Z-./0-9]+$')
    for f in [*files, *ignore_files]:
        if not path_pattern.match(f):
            fail('Wrong file filter:', f)

    cves: list[str] = []
    for cve in cve_set:
        if cve in args_cfg['exclude']:
            continue
        if args_cfg['exploit'] and not hound.get_cve_exploit(cve):
            continue
        if files and not rule_touches(hound.get_rule_files(cve), files):
            continue
        if ignore_files:
            should_check = False
            for rulefile in hound.get_rule_files(cve):
                # Header files don't affect the ignore decision
                if rulefile.endswith('.h'):
                    continue
                # If this file doesn't match any ignore pattern, we should check this CVE
                if not any(rulefile.startswith(x) for x in ignore_files):
                    should_check = True
                    break
            if not should_check:
                continue
        cves.append(cve)

    files.sort()
    ignore_files.sort()
    return sorted(cves)


def tools_report(hound: CVEhound, metadata_path: str | None) -> dict[str, Any]:
    """The `tools` block: everything that decides what a run can find."""
    tools: dict[str, Any] = {}
    tools['cvehound'] = get_cvehound_version()
    tools['spatch'] = '.'.join(list(str(hound.spatch_version)))
    tools['spatch_path'] = hound.spatch
    # The budgets that produced these findings: a rule that timed out here may
    # well have fired on a machine that gave it more room, so a report is not
    # comparable to another one without them.
    tools['spatch_timeout'] = SPATCH_TIMEOUT
    tools['spatch_wall_timeout'] = SPATCH_WALL_TIMEOUT
    # Which transport ran is part of how the numbers were produced, like the
    # budgets above: two reports from different transports are not comparable
    # runs of the same thing.
    tools['spatch_zygote'] = hound.zygote
    tools['spatch_ast_cache'] = bool(hound.astcache)
    # Rules and metadata update out-of-band, so the tool version alone does not
    # identify what produced the findings; pin the content identity too.
    content = resolve_content()
    rules_info: dict[str, Any] = {'source': content.source, 'count': len(hound.cve_all_rules)}
    if content.content_id:
        rules_info['content_id'] = content.content_id
    if content.source_commit:
        rules_info['commit'] = content.source_commit
    tools['rules'] = rules_info
    latest_fix = latest_fix_date(hound.metadata)
    tools['metadata'] = {
        'path': metadata_path,
        'entries': len(hound.metadata),
        'latest_fix_date': fix_date_str(latest_fix) if latest_fix else None,
    }
    return tools


class ReportFile:
    """The --report destination, opened before the sandbox and written after.

    Opened early because Landlock leaves an already-open fd alone, whereas
    granting the report's directory would mean write access to the CWD, which is
    routinely $HOME. No O_TRUNC either: a run that dies partway leaves the
    previous report in place rather than an empty file, and a file this run
    created is removed again on any failure -- an empty report.json parses worse
    than no report.json.
    """

    def __init__(self, path: str | None) -> None:
        self.path = path
        self.fd: int | None = None
        self.created = False

    def __enter__(self) -> 'ReportFile':
        if self.path:
            self.created = not os.path.exists(self.path)
            try:
                self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, 0o666)
            except OSError as err:
                fail("Can't open report file:", err)
        return self

    def write(self, report: dict[str, Any]) -> None:
        if self.fd is None:
            return
        with os.fdopen(self.fd, 'w', encoding='utf-8') as fh:
            self.fd = None
            fh.truncate(0)
            json.dump(report, fh, indent=4, sort_keys=True)
        print('Report saved to:', self.path)

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self.fd is not None:
            with contextlib.suppress(OSError):
                os.close(self.fd)
            self.fd = None
        if exc_type is not None and self.created and self.path:
            with contextlib.suppress(OSError):
                os.unlink(self.path)


def confine(
    kernel: str,
    hound: CVEhound,
    metadata_path: str | None,
    mode: str,
    repo: GitRepo | None = None,
) -> None:
    """Install the sandbox, or exit. Must be the last thing before the pool:
    no thread and no child exists yet, so the one call covers the workers, the
    spatch each of them runs, and the /bin/sh, git, find, rm and diff spatch
    runs in turn.

    A repo's cat-file children count as children: they are reaped here, so an
    open pipe cannot outlive the lock unconfined, and the repository is granted
    read-only so they can reopen for the git questions asked afterwards.
    """
    if repo is not None:
        repo.close()
    if mode == 'off':
        return
    try:
        install_sandbox(
            kernel,
            resolve_content().rules_dir,
            hound.spatch,
            metadata_path,
            astcache=hound.astcache,
            strict=mode == 'strict',
            extra_read=repo.read_paths() if repo is not None else (),
        )
    except SandboxError as err:
        fail(err)


@dataclass
class Outcome:
    """What one task came back with: a verdict, or the error record a report
    carries in place of one."""

    result: dict[str, Any] | bool = False
    error: dict[str, Any] | None = None


def error_record(cve: str, err: Exception) -> dict[str, Any]:
    """The report['errors'] entry for a failed check, logged as it is built.
    Anything not listed here is a bug, and propagates."""
    if isinstance(err, SpatchTimeout):
        logging.error(str(err))
        return {
            'error': 'timeout',
            'returncode': err.returncode,
            'timeout': err.timeout,
            'wall': err.wall,
            'files': err.files,
            'stderr': err.stderr_tail,
        }
    if isinstance(err, SpatchTruncated):
        # Before SpatchError, its base: an incomplete scan is the environment's
        # (a torn AST-cache entry, a full disk), and the record says which files
        # went unscanned so the report cannot be read as clean for them.
        logging.error(str(err))
        return {
            'error': 'truncated',
            'returncode': err.returncode,
            'files': err.files,
            'exceptions': err.kinds,
            'retried': err.retried,
            'stderr': err.stderr_tail,
        }
    if isinstance(err, SpatchError):
        logging.error(str(err))
        return {'error': 'spatch', 'returncode': err.returncode, 'stderr': err.stderr_tail}
    if isinstance(err, UnsupportedVersion):
        logging.error('Skipping: ' + err.cve + ' requires spatch >= ' + err.rule_version)
        return {'error': 'unsupported_version', 'requires': err.rule_version}
    if isinstance(err, PcreGrepNotFound):
        # Reported per rule rather than aborting: only the handful of
        # .grep rules need PCRE, and the cocci ones -- the overwhelming
        # majority -- are unaffected. Recorded as an error, never a
        # clean verdict, so a report cannot claim these were checked.
        logging.error('Skipping: ' + cve + ': ' + str(err))
        return {'error': 'no_pcre_grep'}
    raise err


def run_pool(hound: CVEhound, loglevel: int, tasks: Iterable[Task]) -> dict[Task, Outcome]:
    """Fan the tasks out over one process per CPU and collect what came back.

    The one and only parallel layer besides spatch's own -j: callers add tasks,
    never pools.
    """
    # Under forkserver (the Linux default since Python 3.14) workers would
    # otherwise each re-import cvehound when the CLI runs as `python -m
    # cvehound`; preloading amortizes that once. No-op for fork/spawn.
    multiprocessing.set_forkserver_preload(['cvehound.worker'])
    outcomes: dict[Task, Outcome] = {}
    with concurrent.futures.ProcessPoolExecutor(
        max_workers=os.cpu_count(), initializer=_worker_init, initargs=(hound, loglevel)
    ) as executor:
        future_to_task = {
            executor.submit(_worker_check_cve, cve, all_files, tree): (cve, all_files, tree)
            for cve, all_files, tree in tasks
        }
        for future in concurrent.futures.as_completed(future_to_task):
            task = future_to_task[future]
            try:
                outcomes[task] = Outcome(result=future.result())
            except Exception as err:
                outcomes[task] = Outcome(error=error_record(task[0], err))
    return outcomes


def fold_outcomes(report: dict[str, Any], outcomes: dict[Task, Outcome]) -> None:
    """A flat scan's results and errors, keyed by CVE.

    'errors' is part of the schema whether or not anything failed: a consumer
    that has to tell "no CVE fired" from "the rule never ran" needs the key to
    be there unconditionally.
    """
    report.setdefault('results', {})
    report.setdefault('errors', {})
    for (cve, _, _), outcome in outcomes.items():
        if outcome.error is not None:
            report['errors'][cve] = outcome.error
        elif outcome.result:
            report['results'][cve] = outcome.result


def disable_astcache(args_cfg: dict[str, Any]) -> None:
    """Cache entries embed the absolute source path, and a materialized tree
    lives under a fresh mkdtemp: every entry would be a write with no possible
    later hit. Without this, ast_cache=None means $CVEHOUND_SPATCH_ASTCACHE."""
    if args_cfg.get('cache'):
        logging.info('AST cache: disabled for temporary trees (they never hit it)')
    args_cfg['cache'] = 'none'


def quiet_loglevel(loglevel: int) -> int:
    """The level for checks whose verdicts the caller reports itself: the
    "Found:" line stays out unless debugging was asked for."""
    return loglevel if loglevel <= logging.DEBUG else logging.ERROR


def configure_logging(verbose: int) -> int:
    loglevel = logging.DEBUG if verbose > 1 else logging.INFO if verbose else logging.WARNING
    setup_logging(loglevel)
    return loglevel
