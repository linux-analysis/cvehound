# AGENTS.md

Notes for coding agents working in this repository.

CVEhound checks Linux kernel sources for known CVEs using Coccinelle semantic patches
and grep patterns. See `README.md` for what it does, how to install it, and the CLI.

This file covers only what you can't infer from reading the code or the other docs.

## Where to look

| Task | Read |
| --- | --- |
| Write a detection rule | the `write-cve-rule` skill (`.agents/skills/write-cve-rule/`) |
| Rule-writing reference | `docs/WRITING_RULES.md` (complete guide) |
| Look up Coccinelle syntax | `docs/COCCINELLE_CHEATSHEET.md` |
| Start a new rule | `contrib/blank.cocci`, `contrib/template.cocci` |
| Install / CLI usage / dev setup | `README.md` |

Don't restate those docs here. If something belongs in one of them, put it there.

The skill is the workflow, `docs/WRITING_RULES.md` is the reference behind it. Codex loads
skills from `.agents/skills/`; `.claude/skills/write-cve-rule` is a symlink to the same
directory so Claude Code finds it too. Edit the real files under `.agents/`.

## Adding a CVE rule

Drop a file in `cvehound/cve/CVE-YYYY-NNNNN.cocci` (or `.grep`). That is the whole
change — **do not add test cases**. Rules are auto-discovered by `get_rule_cves()`
(`cvehound/util.py:92`) and every test is auto-parametrized over them by
`pytest_generate_tests` (`tests/conftest.py:284`).

Put disputed CVEs in `cvehound/cve/disputed/`. Directory placement is the only thing
that drives the `all` / `assigned` / `disputed` groups for `--cve` (default:
`assigned`); the split keys off `'disputed' in root` in `get_rule_cves()`.

### A rule's literal tokens are a cost input, not just a pattern

What a rule spells literally decides how much of the tree spatch parses on a whole-tree
scan (`test_06`, `--all-files`) — CVE-2020-12352 cost 632 CPU-seconds per scan for zero
candidate files. `validate-rule.sh` measures it; `docs/WRITING_RULES.md` → "Rule 8: Keep
the grep query selective" explains it.

That cost is now bounded, not just documented: `SPATCH_TIMEOUT` and
`SPATCH_WALL_TIMEOUT` in `cvehound/__init__.py`, both failing the CVE with
`SpatchTimeout`. `docs/WRITING_RULES.md` → "The rule exceeds its time budget" has the
values, what each one counts, and why a fired `--timeout` has to be read off stderr
rather than the exit code.

### Metadata headers are test inputs, not documentation

The leading `///` block (`Files:`, `Fix:`, `Fixes:`/`Detect-To:`, `Version:`) is parsed at
`cvehound/__init__.py:315-329` and documented in
`docs/WRITING_RULES.md` → "Metadata Fields Explained".

What that reference can't convey is why it matters here: the whole slow test suite is
generated from `Fix:` and `Fixes:`/`Detect-To:`, so a wrong hash is a failing test, not a
typo:

| Test | Asserts |
| --- | --- |
| `test_01_on_branch` (fast) | not detected on the supported stable branches |
| `test_02_on_init` | at `v2.6.12-rc2`, detected only if `Fixes:` is the initial commit |
| `test_03_on_fix` | detected at `Fix~`, not at `Fix` |
| `test_04_on_fixes` | detected at `Fixes`, not at `Fixes~` |
| `test_05_between_fixes_fix` | detected at every tag (`-rc` included) in `Fixes..Fix~` where `Files:` changed (`--between-mode=commits`: every touching commit) |
| `test_06_on_branch_all_files` | same as `test_01` but with `all_files=True` |

Register legitimate failures as data, never as `xfail` in a test file:

- `missing_backports` — `tests/conftest.py:30`, a list of `(cve, branch)` pairs consumed
  by `@pytest.mark.notbackported` in `test_01` and `test_06`. The xfail it produces is
  **strict**: when the backport finally lands the pair XPASSes and the suite fails, which
  is the signal to delete it. `tests/test_08_exceptions.py` covers the staleness the
  strict xfail cannot see — a pair naming a rule or a branch that no longer exists is
  never collected at all, so it fails that lint instead.
- `ownfixes` — `tests/test_00_metadata.py:26`, `(cve, reason)` pairs for CVEs whose
  upstream `Fixes:` tag is wrong.

### Gotcha: a `Files:` path that resolves nowhere is silent

If none of a rule's `Files:` paths exist in the tree, `check_cve` skips the rule unless
`all_files=True`, so a bad path is a false negative rather than an error. A typo does this;
so does a rename, because the tests run the rule across the whole `Fixes..Fix` range and on
old stable branches. List every name the file has had in that range, not just the current
one. The validator checks both ends of the range and prints the historical name when the
older end has none.

## Tests

```bash
uv run pytest                       # fast tests only
uv run pytest --runslow             # the real suite (needs a kernel checkout)
uv run pytest --cve=CVE-2020-12912  # one CVE
```

Custom options (`tests/conftest.py`, `pytest_addoption`): `--runslow`, `--runmetadata`, `--cve`,
`--branch`, `--dir`, `--between-mode=tags|commits`, `--no-result-cache`. Markers (`pytest.ini`):
`slow`, `fast`, `notbackported`, `ownfixes`, `nometadata`, `metadata`.
`--strict-markers` is on, so a misspelled marker is a hard error. `--cve` deselects every
test not parametrized by cve (the harness unit tests); name paths explicitly to combine,
e.g. `pytest --cve=X tests/test_12_kerneltree.py`.

The suite runs parallel by default (`-n auto --dist loadgroup` in `pytest.ini`); pass `-n0`
for a sequential run when debugging. Tests 01-05 never touch the working tree: they check
rules against per-commit mini-trees materialized from git blobs
(`cvehound/oracle/kerneltree.py`), and verdicts are memoized in `tests/.result_cache/`
keyed by rule bytes + blob signature + spatch/python version
(`cvehound/oracle/resultcache.py` — bump `HARNESS_EPOCH` when check semantics
change; `--no-result-cache` bypasses). Only `test_06` needs full trees: one detached
worktree per branch under `/tmp` (`CVEHOUND_TEST_WORKTREES=0` falls back to checkouts of
the shared tree, serialized via one xdist group). `CVEHOUND_TEST_OFFLINE=1` skips the
remote fetches; they are also skipped when `FETCH_HEAD` is younger than 6 hours.

Note that *no* test run is dependency-free: `pytest_configure` always clones or fetches
the kernel into `tests/linux` and constructs a `CVEhound` instance, so `spatch` and
network access are needed even for the fast tests.

Agent command runners often use non-interactive shells, so they may not load OPAM's PATH
setup from shell startup files or prompt hooks. If OPAM installed `spatch` but pytest
cannot find it, initialize OPAM in the same command before running tests:

```bash
eval "$(opam env --shell=bash)"
command -v spatch
uv run pytest --cve=CVE-2020-12912
```

If no switch is selected, add `--switch=<switch> --set-switch` to `opam env`.

`uv sync --extra spatch` sidesteps all of that: it pulls the
[cvehound-spatch](https://github.com/linux-analysis/cvehound-spatch) wheel into the venv, and
`find_spatch()` prefers it over `PATH`. That binary is built without Python scripting, so
a rule that reintroduces `@script:python@` fails there with exit 255 — which is the point.

The kernel checkout is not yours — the fixture runs `head.reset()` plus
`git clean -f -x -d` on it whenever the tree is dirty. It also needs full history plus
`stable` and `next` remotes, so never shallow-clone it. `pytest_configure` applies git
performance settings to it (parallel checkout, `feature.manyFiles`, a one-time
Bloom-filter commit-graph marked by the `cvehound.commitgraphbloom` config key).

## Conventions

Style is mechanically enforced — run `uv run pre-commit run --all-files` instead of
hand-applying rules. Ruff lints with `E,F,W,I,UP,B,C4,SIM,ANN` and formats the code, so
things like bare `except`, dead imports, and deprecated APIs are already caught.

Two rules ruff enforces that you will otherwise get wrong by default:

- **Single quotes** (`quote-style = "single"`), line length 100.
- **Type annotations are mandatory** in `cvehound/` (`ANN`), with per-file exemptions for
  `tests/**`, `cvehound/kbuild.py`, and `cvehound/kbuildparse/**`. `ty` type-checks
  `cvehound/` and excludes those same kbuild paths — the kbuild fork is intentionally
  untyped, so don't "fix" it. (The fork has knowingly diverged from the dead Undertaker
  upstream: seeding, path normalization, and `$(srctree)`/`$(SRCARCH)` handling are
  local changes; diff-ability with upstream is not a goal.)

`uv-lock` is a pre-commit hook: any `pyproject.toml` dependency edit needs a regenerated
`uv.lock` in the same commit.

Commit prefixes follow conventional commits, plus two local ones: `rules:` for CVE rule
changes and `contrib:` for templates.

## Architecture notes

`check_cve(cve, all_files=False, jobs=1) -> dict | bool` (`cvehound/__init__.py`) is the only
detection entry point; it returns a result dict on a hit and `False` otherwise. There is
no `check_kernel()` and no `get_report()` — iteration over CVEs and JSON report assembly
live in the CLI.

The CLI is subcommands under `cvehound/cli/`: `__init__.py` dispatches (`scan` is the
default, so bare `cvehound --kernel DIR` is unchanged), `common.py` holds the stages every
subcommand shares (settings merge, hound, CVE selection, report file, pool), and
`scan.py`/`diff.py`/`bisect.py` are one `main(args, prog) -> int` each. `cvehound/__main__.py`
is a two-line shim; `cvehound/scripts/update.py` is dispatched the same way it always was.

Parallelism is already two-level: `common.run_pool()` fans out with
`ProcessPoolExecutor(max_workers=os.cpu_count())` and each `spatch` is invoked with `-j`.
Don't add another layer. The pool callables live in `cvehound/worker.py`, not in the CLI
modules — under spawn/forkserver (the Linux default since Python 3.14) they are pickled by
qualified name, and `python -m cvehound` makes `cvehound.__main__` unresolvable in workers.
Keep them, and anything they call at import time, importable. A task is
`(cve, all_files, tree | None)`; the git modes pass one materialized directory per revision.

Git access goes through `cvehound/gitrepo.py` (`GitRepo`, plain subprocess, persistent
`cat-file --batch` pipes) and nowhere else; it implements the `ObjectReader` protocol that
`cvehound.oracle.BlobMaterializer` consumes, which is how the CLI and the test suite share
the mini-tree machinery without the CLI depending on GitPython. `cvehound/gitrev.py` turns a
revision into a directory (`tree_paths()` is the union of every rule's `Files:` plus the
arch Makefiles, plus the Kbuild files under `--kernel-config`) and holds the pure
classification helpers; `cvehound/gitevidence.py` is the zero-spatch layer (fix in history?
range cites known fixes?). Two ordering rules there are load-bearing: every tree is
materialized and every `GitRepo` pipe closed *before* `confine()`, and the evidence pass
that runs *after* the pool needs the repository's git dir granted read-only
(`extra_read` in `sandbox.build_policy`), because under `--rev` the scanned directory is
a temp tree and the repository is not beneath it. Evidence annotates findings; the only
thing that ever drops a rule on git's say-so is the opt-in `--prune-unintroduced`.

Detection content (rules + metadata) resolves through `resolve_content()`
(`cvehound/content.py`): a verified content overlay under
`$XDG_DATA_HOME/cvehound/content/` when one is installed, else the packaged baseline.
`cvehound update` installs overlays (atomically, checksummed against a manifest from the
rolling `content-latest` GitHub release built by `.github/workflows/content.yml`); it
never writes into the installed package. Two guardrails matter here: in an editable
install the repo's own content always wins unless `CVEHOUND_CONTENT` is set explicitly,
and `tests/conftest.py` pins `CVEHOUND_CONTENT=none` so the suite always parametrizes
over the repo's rules.

The metadata blob `cvehound/data/kernel_cves.json.gz` is **not git-tracked**: the weekly
`content.yml` job regenerates it (kernel clone + `cvehound_update_metadata`, a
maintainer/CI tool — not for end users) and publishes it as a `content-latest` asset;
`publish.yml` copies it into the package at release-build time, and the test suite
downloads it into the cache dir when the checkout has none. Precedence at runtime:
`--metadata` → `$CVEHOUND_METADATA` → overlay → packaged. CLI defaults can also come
from `/etc/cvehound.ini` or `~/.config/cvehound.ini` (`--config`).

`cvehound/sandbox.py` confines a scan with Landlock and seccomp (pure `ctypes`, no new
dependency). Its install point, `confine()` in `cvehound/cli/common.py` immediately before the pool, is
load-bearing rather than incidental: both mechanisms are inherited across fork *and*
execve, so one call there covers the workers, every spatch, and everything spatch shells
out to — but only while no thread or child exists yet. The module's own docstring covers
the rest, including why a too-tight policy fails silently.

When a rule is a judgement call, prefer a false positive: a missed CVE is worse than a
noisy one.
