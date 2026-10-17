[![GitHub Actions status](https://github.com/linux-analysis/cvehound/workflows/test/badge.svg)](https://github.com/linux-analysis/cvehound/actions?query=workflow%3Atest)
[![Supported Versions of Python](https://img.shields.io/pypi/pyversions/cvehound.svg)](https://pypi.org/project/cvehound)
[![PyPI package version](https://img.shields.io/pypi/v/cvehound.svg)](https://pypi.org/project/cvehound)

# CVEhound

CVEhound is a tool for checking Linux sources for known CVEs.
The tool is based on [coccinelle](https://coccinelle.gitlabpages.inria.fr/website/)
rules and grep patterns. The tool checks sources for vulnerable
code patterns of known CVEs and missing fixes for them.

- **What:** The tool tries to find "unfixed" code of known CVEs;
- **How:** The tool uses [coccinelle/grep](cvehound/cve) rules with patterns that helps to detect known CVE bugs or their fixes. Thus, sources are checked either for a presence of "unfixed" code pieces (e.g. [CVE-2020-12912](cvehound/cve/CVE-2020-12912.cocci)), or for an absence of a fix (e.g. [CVE-2020-26088](cvehound/cve/CVE-2020-26088.cocci));
- **Why:** If you have a git log then it's easier to check what CVEs are fixed based on a git history. However, many vendors (samsung, huawei, various iot, routers manufacturers) publish kernel sources as archives without a development log. In most cases their kernels are based on LTS kernels, but versions are far from upstream. Linux version string from Makefile will only give you information about what CVEs were fixed by kernel developers up to this version. It will not help you to understand what fixes were backported by a vendor itself. In this case it's possible to apply the tool and check "missing" CVE fixes.

### CVEHound: Audit Kernel Sources for Missing CVE Fixes

[Linux Security Summit 2021 Presentation (EN)](docs/LSS2021_CVEhound_en.pdf)

<p align="center">
  <a href="https://www.youtube.com/watch?v=jIDnVeZNUA8">
    <img src="https://img.youtube.com/vi/jIDnVeZNUA8/0.jpg" alt="Linux Security Summit 2021 Presentation"/>
  </a>
</p>

[ZeroNights 2021 Presentation (RU)](docs/ZN2021_CVEhound_ru.pdf)

<p align="center">
  <a href="https://www.youtube.com/watch?v=-QwLkpYzQIk">
    <img src="https://img.youtube.com/vi/-QwLkpYzQIk/0.jpg" alt="ZeroNights 2021 Presentation"/>
  </a>
</p>

### Found issues in stable trees

 - CVE-2020-27825 fix [missing backports](https://lkml.org/lkml/2021/1/21/1278) for [5.4, 4.19, 4.14, 4.9, 4.4 kernels](https://www.spinics.net/lists/stable/msg440412.html)
 - CVE-2021-4149 fix [missing backports](https://lore.kernel.org/stable/d1a3f31f-2205-6dce-0f33-6611972e48cd@gmx.com/T/#t) to [4.19, 4.14, 4.9 kernels](https://lore.kernel.org/stable/20220309064748.160978-1-denis.e.efremov@oracle.com/)
 - CVE-2022-26490 fix [missing backports](https://lore.kernel.org/all/20220321174006.47972-1-denis.e.efremov@oracle.com/)
 - CVE-2023-1989 fix missing backports for [6.1, 5.15, 5.10, 5.4, 4.19, 4.14 kernels](https://lore.kernel.org/stable/20230902102200.24474-1-efremov@linux.com/)
 - Similar to CVE-2021-28660 [fix in r8188eu driver](https://lore.kernel.org/all/20220518070052.108287-1-denis.e.efremov@oracle.com/#r)
 - Similar to CVE-2021-28660 [fix in rtl8723bs driver](https://lore.kernel.org/all/20220520035730.5533-1-efremov@linux.com/)
 - Similar to CVE-2022-26490 [fix](https://lore.kernel.org/all/20221122004246.4186422-4-mfaltesek@google.com/) in [st-nci driver](https://lore.kernel.org/all/fc85ff14-70d6-0c3e-247d-eda2284a5f6b@oracle.com/)
 - Security [regression CVE-2020-10781](https://lkml.org/lkml/2023/4/17/744)
 - See [`missing_backports` in the tests](https://github.com/linux-analysis/cvehound/blob/main/tests/conftest.py) for more examples

## Installation

``` shell
$ python3 -m pip install --user 'cvehound[spatch]'
```

That brings a prebuilt, tailored `spatch` along with the tool
([cvehound-spatch](https://github.com/linux-analysis/cvehound-spatch)), so there is
nothing else to install and no coccinelle build to keep in step. It is used
automatically unless you name another `spatch` explicitly.

Prerequisites: Python 3.11+, `grep` with PCRE support (`-P`), and `diffutils`
(spatch renders what it matched by running `diff`).

The wheel covers Linux on x86_64 and aarch64, and macOS on arm64. Anywhere
else, drop the `[spatch]` part and provide coccinelle (>= 1.1.0) yourself —
`apt install coccinelle`, `dnf install coccinelle`, `brew install coccinelle`. A development
install from a clone takes the extra too: `pip install -e '.[spatch]'`.

### Updating rules and metadata

Detection rules and CVE metadata evolve much faster than the tool. To refresh
both without upgrading cvehound:

``` shell
$ cvehound update
```

Updates are downloaded from the project's rolling `content-latest` GitHub
release, verified against a checksummed manifest, and installed atomically
under `~/.local/share/cvehound/` — the installed package is never modified.
`cvehound update --check` only reports whether an update is available
(exit code 10 when one is, handy for cron), and `cvehound --version` shows
exactly which rules and metadata are in use. If the downloaded content is
missing or invalid, cvehound falls back to the rules and metadata bundled
with the package.

The metadata location can also be pinned with `--metadata <file>` or the
`CVEHOUND_METADATA` environment variable, and default CLI options can be set
in `/etc/cvehound.ini` or `~/.config/cvehound.ini` (see `--config`).

Which `spatch` runs is chosen the same way: `--spatch <path>` (or a `spatch`
key in the config file), else the `CVEHOUND_SPATCH` environment variable, else
the bundled `cvehound-spatch` package if it is installed, else whatever is on
`PATH`. A binary you name explicitly is never silently replaced by a fallback —
if it does not resolve, cvehound stops and says so.

## How to use

The simplest way to start using CVEhound is to run the following command:

``` shell
$ cvehound --kernel ~/linux
Found: CVE-2020-27830
Found: CVE-2020-27152
Found: CVE-2020-29371
Found: CVE-2020-26088
```

where *dir* should point to the Linux kernel sources. CVEhound will check the
sources for all cve patterns that you can find in [cve dir](/cvehound/cve/).
To check the sources for particular CVEs one can use:

``` shell
$ cvehound --kernel ./linux --kernel-config --cve CVE-2020-27194 CVE-2020-29371
Checking: CVE-2020-27194
Found: CVE-2020-27194
MSG: bpf: Fix scalar32_min_max_or bounds tracking
FIX DATE: 2020-10-08 09:02:53
https://www.cve.org/CVERecord?id=CVE-2020-27194
Affected Files:
 - linux/kernel/bpf/verifier.c: CONFIG_BPF & CONFIG_BPF_SYSCALL
   linux/.config: affected
Config: ./linux/.config affected

Checking: CVE-2020-29371
Found: CVE-2020-29371
MSG: romfs: fix uninitialized memory leak in romfs_dev_read()
FIX DATE: 2020-08-21 16:52:53
https://www.cve.org/CVERecord?id=CVE-2020-29371
Affected Files:
 - linux/fs/romfs/storage.c: CONFIG_ROMFS_FS
   linux/.config: not affected
Config: ./linux/.config not affected
```

Other args:
 - `--report` - will produce json file with found CVEs
   Most of the metainformation in the generated report is taken from kernel.org
   vulns.git and CIP kernel-sec. Rules that could not be checked are listed
   separately under `errors` (a rule that blew its time budget, a spatch failure,
   a rule needing a newer spatch), so an empty `results` can be told apart from a
   scan that did not finish
 - `--kernel-config` or `--kernel-config <file>` - will infer the kernel configuration required to
   build the affected code (based on Kbuild/Makefiles, ifdefs are not checked) and
   check kernel .config file if there is one. Files the parser can't map to CONFIG_
   options are reported as `unknown` and counted as affected
 - `--check-strict` - with `--kernel-config`, report only CVEs whose affected files are
   enabled in the .config. A CVE is dropped only when the evaluation explicitly rules
   every affected file out (e.g. the option is disabled, or the file belongs to another
   architecture); files unknown to the Kbuild parser are still reported with a warning
 - `--arch` - kernel architecture to analyze (x86, arm64, ...; ARCH spellings like
   x86_64 are normalized to the arch/ source directory). Defaults to the architecture
   from the .config banner, or x86
 - `--files` - will limit the scope of checked cves to the kernel files of interest
 - `--exploit` - check only for CVEs that are known to be exploitable (according to
   the CISA Known Exploited Vulnerabilities catalog)
 - `--sandbox` - `auto` (default), `off`, or `strict`. Confines the scan with Landlock and
   seccomp so a detection rule cannot reach past the tree it is scanning: the kernel tree
   is read-only, your home directory and the network are unreachable, and only a temp
   directory is writable. `auto` falls back to an unconfined scan when the kernel cannot
   do it (Landlock needs 5.13+, enabled at boot) and says so under `--verbose`; `strict`
   refuses to scan instead. `$CVEHOUND_SANDBOX` sets the default.
 - `--zygote` - `auto` (default), `off`, or `on`. Runs spatch as one warm server per worker,
   forking a fresh process per rule, instead of starting spatch once per rule. `auto` uses it
   when the installed `cvehound-spatch` says it can (the wheel records what it was built with);
   any other spatch keeps one process per rule. Every rule still runs in its own process, so
   this changes what a scan costs, never what it finds.
 - `--cache[=DIR]` - reuse parsed C between rules that target the same file, kept in `DIR`
   (bare `--cache` puts it under the cvehound cache directory, keyed by the spatch that wrote
   it). **Off by default, and worth understanding before turning on:** it costs roughly 310 MB
   per kernel tree scanned, and a first scan of today's rule set is marginally *slower* with it,
   because only about a fifth of the parses repeat. It pays off when you scan the same tree
   more than once (a rescan is ~25% faster) or when running thousands of rules, where the
   repeats dominate. Nothing shrinks the cache on its own, so cvehound evicts least-recently-used
   entries past a few GB, and `--cache-clear` empties it.

## Git trees

When `--kernel` is a git repository, cvehound can answer questions about its
history without checking anything out: the files each rule reads are taken
straight from the object database into a temporary directory, so the working
tree can be dirty, mid-rebase or on another branch entirely. The command line
has subcommands for this; bare `cvehound --kernel DIR` is still `cvehound scan`.

``` shell
$ cvehound scan --kernel ~/linux --rev v6.6.30              # one tag, commit or branch
$ cvehound scan --kernel ~/linux --rev linux-6.1.y linux-5.15.y linux-5.10.y   # side by side
```

A scan of any git tree, `--rev` or not, ends with what history says about each
finding's fix. A fix that is already in the history -- as the upstream commit
or as a stable backport citing it -- and a rule that still fires is the kind of
finding this project exists for: a backport that did not take, or a regression.

```
Found: CVE-2021-4149
git evidence (linux-4.19.y):
  CVE-2021-4149: fix-present (backported as 8d1e2f3a4b5c) -- rule still fires, check the backport
  CVE-2022-0998: fix-absent
  CVE-2020-27825: unknown (fix 3f2a1b9c0d4e not in this repository)
```

Evidence annotates, it never filters: on a rebased or squashed vendor tree no
upstream commit is an ancestor of anything, and `unknown` is the honest answer.
The one opt-in filter is `scan --prune-unintroduced`, which skips rules whose
introducing commit is provably not in the scanned history -- provably, so a
commit the repository does not have keeps the rule.

`cvehound diff` says what a change does to the verdicts. Each rule whose files
the change touches runs at both ends; commit messages are read as well, for the
fix and introducing commits the CVE metadata knows about (which covers CVEs no
rule exists for).

``` shell
$ cvehound diff --kernel ~/linux v6.6.29..v6.6.30
CVE-2024-26595: fixed (detected at v6.6.29, not at v6.6.30)
git history: 14 CVE fixes, 3 candidate fixes
7 rules matched 412 changed files: 1 fixed, 0 introduced, 0 still vulnerable

$ cvehound diff --kernel ~/linux-5.10.y --patch 0001-backport.patch --base linux-5.10.y
$ cvehound diff --kernel ~/linux v6.6.29..v6.6.30 --per-commit      # name the commit that flipped it
$ cvehound diff --kernel ~/linux origin/master..HEAD --fail-on introduced   # exit 3 when a CVE comes back
```

`--patch` applies the patch (or series) in a private index and leaves nothing
behind but dangling objects; `--fail-on introduced` is the pre-receive hook in
two lines:

``` shell
#!/bin/sh
while read old new ref; do cvehound diff --kernel . "$old..$new" --fail-on introduced || exit 1; done
```

`cvehound bisect` finds the commit at which one rule's verdict flipped, in
either direction -- where a fix landed on a branch, or which commit re-opened a
CVE the history says is fixed. It walks only the commits touching the rule's
files, collapses those that leave them unchanged, and bisects the rest:

``` shell
$ cvehound bisect --kernel ~/linux --cve CVE-2014-0100 v3.13..v3.15
CVE-2014-0100: bisecting 243 commits touching net/ipv4/inet_fragment.c (3 distinct contents)
CVE-2014-0100: detected at v3.13, clean at v3.15
CVE-2014-0100: verdict flips at 24b9bf43e93e net: fix for a race condition in the inet frag code (detected -> clean)
spatch runs: 3
```

What these modes do not do: `--all-files` at a revision (a whole-tree scan
needs a whole tree; use `git worktree add`), and rewriting the repository in
any way -- the sandbox keeps it read-only, and the git modes read it through
the same grant.

## Contributing

### Development Setup

The project uses [uv](https://docs.astral.sh/uv/) for dependency and
environment management.

``` shell
# Install uv (once, globally)
$ curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and create the dev environment
$ git clone https://github.com/linux-analysis/cvehound.git
$ cd cvehound
$ uv sync                         # creates .venv and installs dev deps

# Install pre-commit hooks
$ uv run pre-commit install

# Run all linters, formatters, and type checks
$ uv run pre-commit run --all-files

# Run the test suite
$ uv run pytest
```

The project uses:
- **uv** for dependency and environment management
- **ruff** for linting and formatting
- **ty** (beta) for static type checking — replaces mypy; version is pinned via `uv.lock`
- **pre-commit** for automated code quality checks

### Writing CVE Detection Rules

If you'd like to contribute new CVE detection rules, please see our comprehensive guides:

- **[Writing Coccinelle Detection Rules for CVE Patterns](docs/WRITING_RULES.md)** - Complete guide with step-by-step instructions, patterns, and examples
- **[Coccinelle CVE Detection Cheat Sheet](docs/COCCINELLE_CHEATSHEET.md)** - Quick reference for common patterns

Templates:
- `contrib/template.cocci` - Enhanced template with examples and comments
- `contrib/blank.cocci` - Minimal template for new rules

If you use a coding agent, the repository ships a `write-cve-rule` skill in
`.agents/skills/` (picked up by OpenAI Codex, and by Claude Code via `.claude/skills/`).
It drives the workflow above and runs `.agents/skills/write-cve-rule/scripts/validate-rule.sh`,
which you can also call by hand — see [AGENTS.md](AGENTS.md).

## License

Python code is licensed under GPLv3. All rules in cvehound/cve folder are licensed under GPLv2.

## Acknowledgements

I would like to thank the following projects and people behind them:
 - [coccinelle](https://coccinelle.gitlabpages.inria.fr/website/) for the program matching engine
 - [kernel.org vulns.git](https://git.kernel.org/pub/scm/linux/security/vulns.git/) and
   [CIP kernel-sec](https://gitlab.com/cip-project/cip-kernel/cip-kernel-sec) for information
   about Linux CVEs
 - [undertaker](https://vamos.informatik.uni-erlangen.de/trac/undertaker) for mapping kernel configs to .c files
