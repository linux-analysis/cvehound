# Writing Coccinelle Detection Rules for CVE Patterns

This is the complete guide to writing CVEhound detection rules, for humans and coding
agents alike. It covers how to go from a kernel fix commit to a working `.cocci` rule.

Two companion documents:

- [COCCINELLE_CHEATSHEET.md](COCCINELLE_CHEATSHEET.md) — the syntax reference and the
  catalog of vulnerability patterns. This guide assumes it; read it first.
- `AGENTS.md` in the repository root — the repository's own conventions (tests, style,
  architecture).

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Rule Structure and Metadata](#rule-structure-and-metadata)
4. [Coccinelle Basics](#coccinelle-basics)
5. [Choosing a Detection Strategy](#choosing-a-detection-strategy)
6. [Pattern Construction Rules](#pattern-construction-rules)
7. [Pattern Matching Techniques](#pattern-matching-techniques)
8. [Common Vulnerability Patterns](#common-vulnerability-patterns)
9. [Step-by-Step Guide](#step-by-step-guide)
10. [Best Practices](#best-practices)
11. [Common Mistakes to Avoid](#common-mistakes-to-avoid)
12. [Testing Your Rules](#testing-your-rules)
13. [Advanced Techniques](#advanced-techniques)
14. [Execution Model](#execution-model)
15. [Learning from Existing Rules](#learning-from-existing-rules)
16. [Examples Walkthrough](#examples-walkthrough)
17. [Troubleshooting](#troubleshooting)
18. [Additional Resources](#additional-resources)
19. [Contributing](#contributing)
20. [License](#license)

## Overview

CVEhound uses [Coccinelle](https://coccinelle.gitlabpages.inria.fr/website/), a program
matching and transformation tool, to detect vulnerable code patterns in Linux kernel
sources. Each CVE is represented by a `.cocci` file that describes the vulnerable code
pattern or the absence of a fix.

### Two Detection Approaches

CVEhound rules can detect vulnerabilities using two complementary approaches:

1. **Unfixed Code Detection**: Match the vulnerable code pattern directly
   - Example: Detecting insecure permission values, uninitialized variables
   - Use when the vulnerable code has a distinctive pattern

2. **Missing Fix Detection**: Check for the absence of a security fix
   - Example: Detecting missing validation checks or initialization
   - Use when the fix adds new code that wasn't present before

[Choosing a Detection Strategy](#choosing-a-detection-strategy) turns this into a
decision you can make mechanically from the fix diff.

## Prerequisites

Before writing CVE detection rules, you should:

- Understand basic C programming (kernel-level C knowledge is helpful)
- Be familiar with Linux kernel source code structure
- Have Coccinelle installed (version >= 1.0.7)

Gather this information before you write a line of the rule:

- [ ] CVE ID (format: `CVE-YYYY-NNNNN`)
- [ ] Fix commit hash from the Linux kernel git repository
- [ ] The commit that introduced the bug, if it is known
- [ ] The complete diff of the fix (`git show <hash>`)
- [ ] Affected file paths, relative to the kernel root
- [ ] An understanding of what actually makes the code vulnerable

### Recommended Reading

- [Coccinelle Tutorial](https://coccinelle.gitlabpages.inria.fr/website/docs/index.html)
- [Linux Kernel Coding Style](https://www.kernel.org/doc/html/latest/process/coding-style.html)
- The CVE's fix commit from the Linux kernel git repository

## Rule Structure and Metadata

Every Coccinelle rule file in CVEhound follows a consistent structure:

```cocci
/// Files: <affected_files>
/// Fix: <fix_commit_hash>
/// Fixes: <commit_hash> OR Detect-To: <commit_hash>
/// Version: <minimum_spatch_version> (optional)

@<rule_name>@
<metavariable declarations>
@@

<enclosing function>(...)
{
	...
*	<the line that identifies the vulnerability>
	...
}
```

A rule is **match rules only**. The report is the `*`: when the pattern matches, spatch
prints a unified diff with the starred lines removed, and that output is the detection.
Silence means "not vulnerable". There is no script rule, no `position` metavariable and no
`@p` binding — the rules have to run under a spatch built without Python.

### Metadata Fields Explained

The header must be the **first contiguous block of `///` lines** in the file — the parser
stops at the first line that doesn't start with `///`. Each field is assigned by simple
overwrite, so a repeated field keeps only the last occurrence; put all paths on one
`Files:` line rather than on several.

These headers are test inputs, not commentary. The whole slow test suite is generated
from them, so a wrong hash is a failing test.

#### `Files:` (should always be set)
Kernel source paths affected by this CVE, space-separated, relative to the kernel root.

```cocci
/// Files: net/bluetooth/a2mp.c net/bluetooth/mgmt.c
```

Nothing enforces this field, which makes a bad path dangerous rather than loud: if none of
the listed paths exist, `check_cve` silently skips the rule unless the caller explicitly
requests `all_files=True`. A typo can therefore cause a false negative.

Renames fall into the same trap. The tests run the rule over the whole `Fixes..Fix` range
and on old stable branches, so list **every** name the file has had in that range:

```cocci
/// Files: drivers/tty/n_hdlc.c drivers/char/n_hdlc.c
```

With only the current name, the rule is blind at its own `Fixes:` commit -- `test_04`
reports "fails to detect on fixes tag" -- and `test_05` skips every tag before the rename.
`git log --follow --name-only -- <path>` lists the historical names, and `validate-rule.sh`
prints them for you when no listed path resolves at the older end.

#### `Fix:` (required in practice)
The mainline commit that fixed the vulnerability.

```cocci
/// Fix: 26896f01467a28651f7a536143fe5ac8449d4041
```

`test_03_on_fix` checks out this commit (the rule must **not** fire) and its parent (the
rule **must** fire). Omit it and the test crashes rather than skipping. All rules set it.

#### `Fixes:` or `Detect-To:` (one of them required in practice)
Both populate the same field — use exactly one:

- **`Fixes:`** — the commit that introduced the bug, when it's known.
- **`Detect-To:`** — the earliest commit at which the rule must fire, when the introducing
  commit isn't explicitly marked or can only be guessed.

```cocci
/// Fixes: da4458bda237aa0cb1688f6c359477f203788f6a
/// Detect-To: 8abee9566b7e8eecf566c4daf6be062a27369890
```

`test_04_on_fixes` asserts the rule fires at this commit and not at its parent, and
`test_05_between_fixes_fix` checks every commit in `Fixes..Fix~`. The value may also be
the tag `v2.6.12-rc2`, which is special-cased to mean "present since the start of git
history" (around fifty rules use it).

#### `Version:` (optional)
Minimum spatch version, used when the rule needs newer syntax. The value is parsed by
stripping the dots (`1.1.2` → `112`), so the line must contain the bare version and
nothing else — trailing prose makes rule parsing raise `ValueError`. Below this version
`check_cve` raises `UnsupportedVersion` and the tests skip. CVEhound itself supports
coccinelle >= 1.1.0, so the field only matters for syntax introduced after that (older
values still parse but never gate anything).

```cocci
/// Version: 1.1.2
```

## Coccinelle Basics

The syntax reference — metavariable types, ellipsis, the `*` context marker,
alternatives and disjunction, `when` constraints and their path quantifiers, and rule
dependencies — lives in [COCCINELLE_CHEATSHEET.md](COCCINELLE_CHEATSHEET.md). Read it
first; this guide assumes it.

The rest of this document covers what the cheatsheet deliberately leaves out: how to go
from a fix commit to a working rule, and worked examples from real CVEs.

## Choosing a Detection Strategy

Read the fix diff and answer these questions in order. The first "yes" decides the
approach.

```
START: Analyze the fix commit diff
│
├─ Does the fix ADD new code?
│  │
│  ├─ YES → Missing Fix Detection
│  │        Pattern: check for the ABSENCE of the new code
│  │        Example: missing validation check, missing initialization
│  │
│  └─ NO → next question
│
├─ Does the fix CHANGE a value (constant, flag, permission)?
│  │
│  ├─ YES → Unfixed Code Detection
│  │        Pattern: match the OLD (vulnerable) value
│  │        Example: return 0444 → return 0400
│  │
│  └─ NO → next question
│
├─ Does the fix REMOVE code?
│  │
│  ├─ YES → Unfixed Code Detection
│  │        Pattern: detect the presence of the removed code
│  │        Example: a whole vulnerable driver deleted
│  │
│  └─ NO → next question
│
└─ Does the fix REFACTOR or change logic?
   │
   └─ YES → Unfixed Code Detection, or a hybrid
            Pattern: match the distinctive vulnerable shape
            May require multiple rules with dependencies
```

Missing Fix Detection is the trickier of the two: "the check isn't there" is expressed
with `when !=` inside an ellipsis, and it fires on any code that never had the bug in the
first place unless you anchor it to the enclosing function. See
[Example 3](#example-3-missing-initialization---cve-2020-12352).

## Pattern Construction Rules

### Rule 1: The `*` is the report

```cocci
@err@
@@

vulnerable_function(...)
{
*	return 0444;         // context marker: the line to report
}
```

`*` is the context marker, not a wildcard (`...` is). It is not cosmetic, and it is not
just a formatting choice: it *is* the reporting mechanism. On a match spatch prints a diff
of the starred lines; a rule with no `*` matches and reports nothing. Marking also switches
the whole patch into match mode, which flips the default quantification of un-annotated
`...` from `forall` to `exists`, so adding or removing a `*` can change what matches. It
cannot be combined with `-`/`+`.

Every rule here stars a line, so that flip always applies: **`exists` in a rule header is
a no-op in this corpus — do not write it.** It is not a cost knob either; the grep query
is computed without it. When a rule needs a guard to hold on *all* paths, put `when forall`
on that one ellipsis (see "Rule 6").

### Rule 2: Star discipline

Three failure modes, all learned the hard way:

**Star only the rule that reports.** A starred rule prints whenever *it* matches, no matter
what the other rules in the file did. So a `*` on a helper rule — most often a `@fix@` rule
whose job is to recognise the fix — reports on **fixed** trees. That is a false positive on
every patched kernel, and the tests catch it as "fires at Fix".

```cocci
// WRONG: the helper stars, so it reports even when the fix is present
@fix@
symbol nfs_v4_2_minor_ops, nfs41_mig_recovery_ops;
@@

*struct nfs4_minor_version_ops nfs_v4_2_minor_ops = {
	...,
	.mig_recovery_ops = &nfs41_mig_recovery_ops,
	...
};

// CORRECT: the helper only matches; the rule that decides is the one that stars
@fix@
symbol nfs_v4_2_minor_ops, nfs41_mig_recovery_ops;
@@

struct nfs4_minor_version_ops nfs_v4_2_minor_ops = {
	...,
	.mig_recovery_ops = &nfs41_mig_recovery_ops,
	...
};

@err depends on !fix && ops@
symbol nfs_v4_2_minor_ops;
@@

*struct nfs4_minor_version_ops nfs_v4_2_minor_ops = {
	...
};
```

(That is `cvehound/cve/CVE-2015-8746.cocci`.)

**Star only the identifying line(s), not the whole pattern.** With several starred lines
separated by `...`, spatch emits the prefix it managed to match even when the rest of the
pattern fails — so a partial match becomes a report. Star the one line the reader needs to
see; leave the surrounding context unmarked:

```cocci
// WRONG: the kfree() alone reports, even with no use after it
*	kfree(var);
	... when != var = ...
*	use(var);

// CORRECT: the use is what identifies the bug
	kfree(var);
	... when != var = ...
*	use(var);
```

The one exception in the corpus is `cvehound/cve/CVE-2019-19448.cocci`, whose natural
report line is a bare `else`; it stars the whole shape because there is nothing else to
point at.

**Star a line spatch can delete — in every kernel version of the range.** A `*` is a
minus line internally, so it must sit on something deletable everywhere the rule runs,
which is every commit in `Fixes..Fix` plus the stable branches. Two tokens are not:

- **A lone `}` (or `{`).** spatch *silently drops* the star: the branch still matches,
  but contributes nothing to the diff, so the match reports nothing — a false negative
  with no error anywhere. If it is the only star in the file, spatch at least complains
  "doesn't contain any +/-/* code"; buried in one branch of a disjunction it is
  invisible. Star a statement inside the block instead. (Starring a whole statement
  *including* its braces — `*if (...) {` … `*}` — is fine, as are `case X:` labels and
  `else` lines; only an unpaired brace is dropped.)
- **A macro-expanded token.** If *any* version in the range produces the starred token
  by macro expansion, spatch hard-errors with "try to delete an expanded token".
  2.6-era code does this a lot — old `floppy.c` wraps ioctl calls as
  `ECALL(get_floppy_geometry(...))`, so starring the call works on today's tree and
  aborts on 2005's. Unstarred context is allowed to match expanded code; only the star
  is restricted. Star an adjacent plain-token statement (`break;`, an assignment)
  instead.

The validator runs the rule at both ends of the range, which catches both; the deep
history in between is what `pytest --runslow` is for.

### Rule 3: Use appropriate metavariables

```cocci
identifier func;     // For function/variable names (unknown)
symbol kfree;        // Match this exact name literally, not as a metavariable
expression E;        // For any expression
statement S;         // For any statement
type T;              // For any type
```

Full selection table:

| Need to match | Use | Example |
|---------------|-----|---------|
| Unknown function or variable name | `identifier` | `identifier func;` |
| A specific name, matched literally | `symbol` | `symbol kfree;` |
| Any expression | `expression` | `expression E;` |
| Any statement | `statement` | `statement S;` |
| Any type | `type` | `type T;` |
| A specific constant | write it literally | `0444`, `-EINVAL` |
| Any constant | `constant` | `constant C;` |

`symbol` is the one people miss: it declares a name to be matched literally rather than
bound as a metavariable, which matters when the name you want to match could otherwise be
read as a fresh identifier (`symbol current;`). Around fifty rules use it.

Every name left literal — a `symbol`, a spelled-out parameter or field, a constant like
`-EINVAL` — also becomes a token spatch requires before it will open a file, so the
choice has a scanning cost as well as a matching one. Declare what you do not need to
pin; see [Rule 8](#rule-8-keep-the-grep-query-selective).

### Rule 4: Scope the pattern with context

Always provide enough context to avoid false positives:

```cocci
// BAD: too generic, matches across the whole tree
@err@
@@

* return -1;

// GOOD: anchored in the function that has the bug
@err@
@@

vulnerable_function(...)
{
	...
*	return -1;
}
```

### Rule 5: Use ellipsis correctly

```cocci
func(...)              // Match any function arguments
{
	...                // Match 0 or more statements
	code();
	...                // More statements
}
```

### Rule 6: Apply constraints with `when`

```cocci
@err@
identifier var;
@@

func(...)
{
	struct foo var;
	... when != memset(&var, 0, sizeof(var));    // Must NOT have init
		when != var = ...;                        // Must NOT be assigned
*	use_var(&var);
}
```

A `when !=` guard is weaker than it reads. Because `*` puts the rule in `exists` mode, the
guard only has to hold on the single path the engine picks as a witness; every other path
through the function may contain the thing you excluded. In a function with a few branches
that is nearly always satisfiable, so the guard quietly stops narrowing anything.

That errs toward a false positive, which is the side this project prefers. But when a rule
is only *correct* if the guard holds everywhere -- "this lock is never dropped in here",
"this pointer is never reassigned before the deref" -- say so on the ellipsis:

```cocci
	... when != mutex_unlock(&lock)
	    when forall
```

`when forall` is the only way to ask for that. A rule header cannot: `exists` there is a
no-op, and `forall` there would apply to every ellipsis in the rule, including the ones
that need to stay permissive. The corpus has exactly one instance
(`cvehound/cve/disputed/CVE-2021-3178.cocci`) -- read it before reaching for this.

### Rule 7: Match the invariant, not the era

A rule does not run against one kernel. It runs against every commit in `Fixes..Fix`,
every tag in between, and the head of every supported stable branch — often fifteen
years of drift in the same function. A pattern that transcribes the exact shape the
code has *today* (the precise condition, the current line layout) breaks every time
that shape changed, and the usual repair — adding one disjunction branch per
historical form — is an arms race the history always wins: the next refactor in the
range is a silent false negative until someone adds branch N+1.

Instead, separate what the rule needs into two parts, each matched as loosely as the
vulnerability allows:

1. **A vulnerable anchor that held for the whole range** — the call or computation
   that *is* the bug's substrate, which existed from `Fixes` to `Fix`. That is what
   gets the star.
2. **The fix's marker, matched by a helper rule** — the check or call the fix commit
   introduced. The error rule is `depends on !fixed`.

`cvehound/cve/CVE-2017-1000112.cocci` is the worked example. The fix guards the UFO
path in `__ip_append_data()` with a `skb_queue_len(queue) <= 1` check. The first
version of the rule transcribed the vulnerable condition itself — seven disjunction
branches, one per historical spelling of the `if`, still missing any era nobody
thought to transcribe. The invariant version is two short rules per protocol family:

```cocci
@fixed4@
expression E;
@@

\(__ip_append_data\|ip_append_data\)(...)
{
	... when any
	if (<+... \(skb_queue_len(E) <= 1\|skb_queue_len(E) == 1\) ...+>) { ... }
	... when any
}

@err4 depends on !fixed4@
@@

\(__ip_append_data\|ip_append_data\)(...)
{
	... when any
*	ip_ufo_append_data(...)
	... when any
}
```

"Calls `ip_ufo_append_data()` and nothing in the function checks `skb_queue_len`" is
true in every vulnerable version regardless of how the condition was spelled, false at
the fix, and vacuously false once UFO was removed entirely. As a bonus it ran ~100×
faster than the seven-branch version, whose condition disjunctions dominated the
matching cost.

The loosening toolbox, in the order to reach for it:

- `\(old_name\|new_name\)` for identifiers that were renamed in the range
- `<+... e ...+>` for "the expression appears somewhere in this condition", when the
  surrounding expression drifted — an expression context only; to say "anywhere in this
  function body" use `... when any`, which means the same thing far more cheaply (see
  [Restricting a Pattern to Particular Functions](#restricting-a-pattern-to-particular-functions))
- `... when any` for "anywhere in the function", when position within the function
  drifted
- a `@fixed@` helper + `depends on !fixed` instead of writing the vulnerable
  condition at all, when the condition itself is what drifted

When choosing how tight to make the `@fixed@` marker, remember which way the errors
fall: a marker that is too *specific* fails to recognise an odd backport of the fix
and fires — a false positive; a marker that is too *loose* matches something that is
not the fix and stays silent — a false negative. Prefer the specific marker: a missed
CVE is worse than a noisy one.

### Rule 8: Keep the grep query selective

Three rules, then why:

- **Don't spell out a name a metavariable would carry.** Parameter and field names are
  the usual culprits: `ctx->release_agent = param->string` requires `string`,
  `&laddr->a` requires `a`, `current->thread` requires `thread`. Declaring them drops
  the token and the fragility together. Watch the reverse too — CVE-2023-50431 declared
  `identifier sec_attest_info` and then used that name as the function header, so the
  one rare token in the rule was not required at all. See
  [Rule 3](#rule-3-use-appropriate-metavariables) for which metavariable to reach for.
- **Collapse alternatives with `\(A\|B\)`, not an identifier list.** `identifier x = {A,
  B};` looks like the tidier spelling of the same choice, but the constraint never reaches
  `get_constants2.ml`: the rule ends up requiring only `x`, so `A` and `B` drop out of the
  query exactly as if `x` were unconstrained. Collapsing CVE-2021-38209's three subscripts
  keeps `NF_SYSCTL_CT_MAX || NF_SYSCTL_CT_EXPECT_MAX || NF_SYSCTL_CT_BUCKETS` as a
  disjunction and loses all three as an identifier list. Nothing in the corpus uses an
  identifier list; this is why.
- **Give every rule one rare token.** `kmalloc`, `GFP_KERNEL`, `ENOMEM`, `memcpy`,
  `current`, `task_struct`, `u32`, `s32`, `EINVAL` are in half the tree. A pattern built
  only from those needs anchoring in a named function.
- **Keep the rules that star something at five or fewer.** Past that the query can be
  discarded outright and the rule parses the whole tree.

Measure it — this is what `validate-rule.sh` reports, and it is the authority when the
rules above disagree with each other:

```bash
spatch --no-includes --include-headers --chunksize 1 -j 1 \
       --cocci-file cvehound/cve/CVE-YYYY-NNNNN.cocci tests/linux/lib 2>&1 >/dev/null |
  sed -n '/no inferred keywords/{p;q}; /files match/{p;q}'
```

`no inferred keywords` means there is no query at all. Otherwise spatch reports how many
of the 745 files it will parse; a healthy rule reports **0**, or only its own `Files:` if
those live under `lib/`. `spatch --parse-cocci <rule> | grep -A1 'Grep query'`
prints the tokens themselves when you need to see which one is too common.

**Why.** Before parsing anything spatch extracts the literal tokens the rule cannot match
without (`parsing_cocci/get_constants2.ml`) and skips every file whose text contains none
of them (`worth_trying`, `cocci.ml`); each survivor is then parsed in full. On a
whole-tree scan — `cvehound --all-files`, and `test_06` for every rule on every branch —
that filter is the difference between a one-second run and a ten-minute one. A
`... when != X` clause contributes nothing, since negated code cannot be required; only
the positive part of the pattern feeds the query.

The five-rule ceiling comes from the CNF conversion, which gives up once more than
`max_cnf = 5` of the disjuncts need more than one clause — which any rule requiring two
or more tokens does. On spatch 1.0.8 through at least 1.3.2, giving up returns *no*
query. Only rules that modify something join that disjunction: a rule matched purely as
context — a `@fixed@` marker, anything a later rule reaches through `depends on` — is
folded into its dependent instead. `cvehound/cve/CVE-2023-42753.cocci` has seven rules,
one starred, and keeps its query. CVE-2020-12352 had ten starred and cost 632 CPU-seconds
per whole-tree scan for zero candidate files; collapsed into the single rule that
expresses the same invariant, it costs 1.5. If a CVE really needs many sites, look for
the pattern they share before writing them out one by one.

One rule in the corpus warns and should: CVE-2021-20268 detects
`signed_add32_overflows(s64 a, s64 b)`, where the wrong type *is* the bug, so `s64` has
to stay literal. It also spells out `a` and `b`, which looks like the first mistake above
— but a token every rule requires survives the CNF as a clause of its own, so those two
are what force a candidate file to contain both; declaring them leaves only pairs that
`s32` or `s64` already satisfy and takes the rule from 7 files to 20. Measure before
assuming a literal is dead weight.

### Pattern complexity: prefer the simplest thing that works

**Simple — one rule, direct match, minimal context.** This is the target. It is fast and
it is what most rules in `cvehound/cve/` look like:

```cocci
@err@
@@

function(...)
{
*	return 0444;
}
```

**Medium — two or three rules with a dependency**, for "the fix introduced X, so only
look for the bug where X exists". Only the last rule stars:

```cocci
@has_feature@
@@

init_function(...)

@err depends on has_feature@
@@

caller(...)
{
*	usage(...);
}
```

**Complex — many rules, alternatives, several detection points.** Only reach for this
when the vulnerability genuinely requires checking multiple conditions or when simpler
patterns produce too many false positives. "The CVE affects many similar functions" is
usually *not* such a case: see [Rule 8](#rule-8-keep-the-grep-query-selective) for why
one rule that captures the shared invariant beats one rule per function, and
`cvehound/cve/CVE-2020-12352.cocci` for what that looks like.

## Pattern Matching Techniques

### Matching Function Calls

```cocci
// Match any call to a specific function
@rule@
@@

target_function(...);

// Match with specific arguments
@rule@
expression E;
@@

target_function(E, NULL);

// Match function definition
@rule@
identifier func;
@@

int func(int param1, char *param2)
{
	...
}
```

### Matching Struct Members

```cocci
// Match struct field access
@rule@
identifier s;
@@

s->field = 0;

// Match struct initialization
@rule@
@@

struct my_struct s = {
	.field1 = value1,
	.field2 = value2,
};
```

### Matching Conditionals

```cocci
// Match specific condition
@rule@
expression E;
@@

if (E < 0)
	return E;

// Match any conditional
@rule@
statement S;
@@

if (...)
	S
```

### Matching Return Statements

```cocci
// Match specific return value
@rule@
@@

* return -EINVAL;

// Match return with expression
@rule@
expression E;
@@

return E;
```

### Alternative Patterns

Use `\( ... \| ... \)` for alternatives — most often when the same bug lives in several
related functions:

```cocci
// Match any of these function calls
@rule@
@@

\(function1\|function2\|function3\)(...);

// The same bug across renamed variants of one function
@err@
@@

\(follow_page_pte\|follow_page_mask\|follow_page\)(...)
{
*	vulnerable_pattern;
}
```

This is how a single rule keeps working across kernel versions that renamed the function.

### Disjunction

Use `( ... | ... )` within pattern context:

```cocci
@rule@
expression E;
@@

(
* E = unsafe_function1(...);
|
* E = unsafe_function2(...);
)
```

## Common Vulnerability Patterns

The pattern catalog lives in
[COCCINELLE_CHEATSHEET.md](COCCINELLE_CHEATSHEET.md#common-vulnerability-patterns) —
uninitialized variable, missing NULL/bounds check, use-after-free, information leak,
incorrect permission, missing lock, integer overflow. Each entry there names real rules
in `cvehound/cve/` to read alongside it.

Pick the entry matching what the fix did (per
[Choosing a Detection Strategy](#choosing-a-detection-strategy)), then open the real
rules it cites and follow those rather than the sketch.

## Step-by-Step Guide

### Step 1: Understand the CVE

1. Read the CVE description
2. Find the fix commit in the kernel git repository
3. Use `git show <commit_hash>` to see the changes — lines with `-` are the vulnerable
   code, lines with `+` are the fix
4. Identify what makes the code vulnerable

```bash
git show bcf85fcedfdd17911982a3e3564fcfec7b01eebd
```

### Step 2: Choose Detection Strategy

Walk the decision tree in
[Choosing a Detection Strategy](#choosing-a-detection-strategy).

### Step 3: Identify the Code Pattern

Extract the minimal distinguishing pattern. For example, if the fix changed:

```c
// BEFORE (vulnerable):
return 0444;

// AFTER (fixed):
return 0400;
```

The vulnerable pattern is `return 0444;` — but only inside the function the fix touched.

### Step 4: Create the Rule File

Create a file named `CVE-YYYY-NNNNN.cocci` in the `cvehound/cve/` directory, starting
from `contrib/blank.cocci` or the template:

```cocci
/// Files: path/to/affected/file.c
/// Fix: <commit_hash>
/// Fixes: <introduced_commit_hash>

@err@
@@

<pattern goes here, with * on the line that identifies the bug>
```

### Step 5: Write the Pattern

Using the example from Step 3:

```cocci
@err@
@@

some_visibility_func(...)
{
*	return 0444;
}
```

Key points:
- Mark the line to report with `*` — that is the whole reporting mechanism
- Star only that line, and only in the rule that decides
- Anchor the pattern in the enclosing function

### Step 6: Add Context (if needed)

If the pattern is too generic, add more context:

```cocci
@err@
identifier attr;
@@

driver_sysfs_ops(...)
{
	...
	if (attr->mode)
*		return 0444;
	...
}
```

### Step 7: Test the Rule

Check it parses, then run it against the vulnerable and the fixed tree — see
[Testing Your Rules](#testing-your-rules) for the full protocol.

### Step 8: Refine the Pattern

If you get false positives:
- Add more context (function name, surrounding code)
- Use `when !=` constraints
- Add dependencies on other rules

If you miss the vulnerability:
- Simplify the pattern
- Drop literal tokens the fix commit does not carry
- Consider alternatives `\( ... \| ... \)`

### Step 9: Document and Submit

1. Ensure metadata is complete and accurate
2. Add comments explaining complex patterns
3. Run `uv run pytest --runslow --cve=CVE-YYYY-NNNNN`
4. Submit a pull request referencing the CVE and the fix commit

## Best Practices

Three rules matter more than any checklist here:

1. **Anchor the pattern in a named function.** A bare `return -1;` or `kfree(x);` with no
   enclosing context is the most common source of false positives. Nearly every real rule
   in `cvehound/cve/` names the function it matches.
2. **Keep star discipline.** Star only the rule that decides, and only the line that
   identifies the bug — see [Rule 2](#rule-2-star-discipline). A stray `*` on a helper rule
   reports on fixed kernels; a starred multi-line pattern reports on partial matches.
3. **Read three similar rules before writing yours.** They are the ground truth for house
   style, and they encode workarounds this prose cannot:
   `grep -l copy_to_user cvehound/cve/*.cocci`.

For the mechanical checks (does it parse, does it fire at `Fix~`, is it silent at `Fix`),
don't rely on judgement — run the suite, see [Testing Your Rules](#testing-your-rules).

When a rule is a judgement call, prefer a false positive: a missed CVE is worse than a
noisy one.

## Common Mistakes to Avoid

### Mistake 1: Nothing starred

```cocci
// WRONG: the rule matches and reports nothing
@err@
@@

vulnerable_code();

// CORRECT
@err@
@@

* vulnerable_code();
```

### Mistake 2: Pattern too generic

```cocci
// WRONG: will match across the whole tree
@err@
@@

* return -1;

// CORRECT: specific function context
@err@
@@

specific_function(...)
{
	...
*	return -1;
}
```

### Mistake 3: A helper rule stars

A `*` on a `@fix@`-style rule reports on fixed trees. See
[Rule 2](#rule-2-star-discipline) for the worked example.

### Mistake 4: Starring the whole pattern

Several starred lines separated by `...` report the prefix spatch matched, so a partial
match fires. See [Rule 2](#rule-2-star-discipline).

### Mistake 5: Independent sites chained with `depends on`

Separate starred rules are an **OR** — each reports on its own. `depends on` is an **AND**.
Chaining two independent detection sites means neither reports unless both matched:

```cocci
// WRONG if err_a and err_b are independent sites:
@err_a@
@@
...

@err_b depends on err_a@
@@
...

// CORRECT: two independent starred rules, no dependency between them
@err_a@
@@
...

@err_b@
@@
...
```

Conversely, if the CVE is only present when *several* conditions hold, the dependency is
required — see
[Several Detection Sites: OR and AND](#several-detection-sites-or-and-and).

### Mistake 6: `Files:` names no path that exists

If none of the paths exist in the tree, `check_cve` skips the rule instead of erroring
unless the caller explicitly requests `all_files=True`. This can hide a vulnerable kernel,
so verify each path exists at the `Fix` commit -- and, for a file that was renamed, list
the older name too, or the rule resolves nowhere at `Fixes:` and on pre-rename branches.

## Testing Your Rules

### Manual Testing with Spatch

```bash
# Check the rule parses before anything else
spatch --parse-cocci CVE-2020-12345.cocci

# Run it. Do NOT pass --no-show-diff: the diff is the report.
spatch --no-includes --include-headers \
    --very-quiet \
    --cocci-file CVE-2020-12345.cocci \
    file.c
```

A hit is a unified diff of the starred lines — this is `CVE-2022-3106.cocci` on the parent
of its fix commit:

```
--- drivers/net/ethernet/sfc/ef100_nic.c
+++ /tmp/cocci-output-2086817-bb6e21-ef100_nic.c
@@ -609,7 +609,6 @@ static size_t ef100_update_stats(struct
 	ef100_common_stat_mask(mask);
 	ef100_ethtool_stat_mask(mask);

-	efx_nic_copy_stats(efx, mc_stats);
 	efx_nic_update_stats(ef100_stat_desc, EF100_STAT_COUNT, mask,
 			     stats, mc_stats, false);
```

No output at all means the rule did not detect anything. Read the diff, not just its
presence: the starred lines tell you *which* site matched, and a surprising one usually
means the pattern is looser than you meant.

The three checks that matter, run against a kernel checkout:

```bash
# 1. MUST detect on the vulnerable tree
git checkout <fix_commit>~
spatch ... --cocci-file CVE-YYYY-NNNNN.cocci <affected_file>   # expect a hit

# 2. MUST NOT detect on the fixed tree
git checkout <fix_commit>
spatch ... --cocci-file CVE-YYYY-NNNNN.cocci <affected_file>   # expect silence

# 3. MUST NOT fire on unrelated code
spatch ... --cocci-file CVE-YYYY-NNNNN.cocci <unrelated_file>  # expect silence
```

### Testing with CVEhound

```bash
# Test single CVE
cvehound --kernel /path/to/kernel --cve CVE-2020-12345

# Test with config checking
cvehound --kernel /path/to/kernel --kernel-config --cve CVE-2020-12345

# Generate detailed report
cvehound --kernel /path/to/kernel --cve CVE-2020-12345 --report report.json
```

### Using CVEhound Test Suite

You don't add test cases. `tests/conftest.py` discovers every rule in `cvehound/cve/`
and parametrizes the whole suite over them, so a new `.cocci` file is picked up
automatically:

```shell
uv run pytest --runslow --cve=CVE-2020-12345
```

The tests are driven by your metadata headers — `test_03_on_fix` checks out `Fix:` (must
not detect) and `Fix~` (must detect), `test_04_on_fixes` does the same around
`Fixes:`/`Detect-To:`, and `test_05_between_fixes_fix` checks every commit in between.
An incorrect hash shows up as a test failure.

If a CVE legitimately fails — e.g. the fix was never backported to some stable branch —
add it to the `missing_backports` list in `tests/conftest.py` (or `ownfixes` in
`tests/test_00_metadata.py` if the upstream `Fixes:` tag is wrong) instead of editing a
test function.

`missing_backports` entries are strict xfails, so they are not fire-and-forget: once the
stable maintainers backport the fix the test XPASSes and the suite goes red, telling you
to delete the pair. `tests/test_08_exceptions.py` catches the other direction — an entry
naming a rule or a branch that no longer exists, which no test would otherwise collect.

### Validation Checklist

Before submitting:

- [ ] File named `CVE-YYYY-NNNNN.cocci` exactly — uppercase `CVE`, no prefix or suffix
- [ ] Placed in `cvehound/cve/` (or `cvehound/cve/disputed/` for disputed CVEs)
- [ ] `Files:`, `Fix:`, and one of `Fixes:`/`Detect-To:` present and correct
- [ ] Every path in `Files:` exists in the tree at the `Fix` commit
- [ ] Some path in `Files:` exists at `Fixes:`/`Detect-To:` too -- add pre-rename names
- [ ] At least one line starred with `*`, in the rule that decides
- [ ] No helper rule (a `@fix@`-style rule) stars anything
- [ ] Only the identifying line(s) starred, not a multi-line pattern spanning `...`
- [ ] Independent sites are separate starred rules; conditions that must all hold are
      chained with `depends on`
- [ ] Parses: `spatch --parse-cocci CVE-YYYY-NNNNN.cocci`
- [ ] Detects at `Fix~`, silent at `Fix`
- [ ] No false positives on unrelated code
- [ ] `uv run pytest --runslow --cve=CVE-YYYY-NNNNN` passes

## Advanced Techniques

### Several Detection Sites: OR and AND

This is the distinction that most often decides whether a rule is right.

**Independent sites — an OR.** One starred rule per site, no dependency between them. Each
reports on its own:

```cocci
@err_a@
@@

func_a(...)
{
*	vulnerable_call1(...);
}

@err_b@
@@

func_b(...)
{
*	vulnerable_call2(...);
}
```

`cvehound/cve/CVE-2016-5195.cocci` (Dirty COW) is two such sites; `CVE-2020-12352` repeats
the shape ten times, once per affected function.

**Conditions that must all hold — an AND.** Chain the rules with `depends on` so the last
one depends on all the others, and star **only** that last rule:

```cocci
@cond_a@
@@

pattern_a

@cond_b depends on cond_a@
@@

pattern_b

@err depends on cond_a && cond_b@
@@

reporting_function(...)
{
*	the_line_that_identifies_the_bug;
}
```

`cvehound/cve/CVE-2021-3347.cocci` chains three futex functions this way;
`cvehound/cve/CVE-2021-3609.cocci` combines a negative dependency with a positive one
(`depends on !bcm_free_op_rcu && err_bcm_delete_rx_op`). Both star exactly one rule.

The mirror image is just as important: a `@fix@` rule that recognises the fix, gated with
`depends on !fix`, must not star anything — see
[Rule 2](#rule-2-star-discipline).

### Restricting a Pattern to Particular Functions

"Report this only inside `foo()`" is expressed by anchoring the pattern in the function
definition, not by filtering matches afterwards:

```cocci
@err@
identifier pebs_status, cpuc;
@@

intel_pmu_drain_pebs_nhm(...)
{
	... when any
	if (!pebs_status && cpuc->pebs_enabled &&
	    !(cpuc->pebs_enabled & (cpuc->pebs_enabled-1)))
*			pebs_status = cpuc->pebs_enabled;
	... when any
}
```

That is `cvehound/cve/CVE-2021-28971.cocci`. `... when any` on both sides means "anywhere in
the body, nested blocks included", which is what the anchoring needs.

Reach for `<+... ...+>` only in an *expression* context — "this subexpression appears
somewhere in this condition", as in `cvehound/cve/CVE-2017-1000112.cocci`. Wrapping a whole
*statement* body in `<+... ...+>` asks for the same thing but costs far more: on stock
spatch 1.3.2 the `<+...+>` spelling of the rule above takes ~228s on a matching
`arch/x86/events/intel/ds.c` against ~5.8s for the `... when any` spelling, and the slow
suite runs it once per tag in a six-year range.

For several acceptable functions —
including a function that was renamed across the range — use the alternatives syntax:

```cocci
\(__ip_append_data\|ip_append_data\)(...)
{
	...
*	vulnerable_line;
	...
}
```

See `cvehound/cve/CVE-2017-1000112.cocci` and `cvehound/cve/CVE-2016-5195.cocci`.

> **Performance footnote.** The "wrapper" shape — a whole function definition around a
> pattern — was pathological on unpatched spatch 1.3.x, where a single rule could take
> 60-80x longer than the equivalent unanchored one. The bundled spatch carries the
> `satLabel` memoization fix (upstream PR coccinelle/coccinelle#417), so the shape is
> cheap again. If you see a rule of this shape crawl, check which spatch you are running
> before rewriting the rule.

### Matching Macros

Coccinelle expands macros, but you can match macro usage:

```cocci
@err@
@@

// Match macro call
* UNSAFE_MACRO(...);

// Or match the expanded form
* expanded_function(...);
```

### Matching Type Definitions

Detect vulnerable type declarations:

```cocci
@err@
identifier T;
@@

* struct T {
	unsigned int field;  // Should be unsigned long
	...
};
```

## Execution Model

For `.cocci` rules, CVEhound runs `spatch` once per CVE over the paths named in the rule's
`Files:` header. The authoritative flag list is in `check_cve()`
(`cvehound/__init__.py`) — read it there rather than trusting a copy. The flags that
change what your rule sees or prints:

```bash
spatch \
    --no-includes \             # do not resolve #include directives at all
    --include-headers \         # process .h files as inputs in their own right
    --chunksize 1 -j 1 \        # one job here; CVEhound parallelizes across CVEs
    --very-quiet \
    -I <kernel>/arch/<arch>/include ... -I <kernel>/include/uapi ... \
    --include <kernel>/include/linux/kconfig.h \
    --cocci-file <rule> \
    <every path from the rule's Files: header>
```

The match arrives as a unified diff of the starred lines on stdout; no output means no
detection. Because the report is a diff and not a Python `print_report()`, the rules run
under a spatch built without Python support — that is the point of the idiom, and the
reason a rule must never grow a script rule back.

`.grep` rules take a different path entirely: `grep -rPzle <pattern> <files>`.

Note the two-level parallelism: `spatch` is pinned to `-j 1` and `__main__.py` fans out
across CVEs with a `ProcessPoolExecutor`, so don't add another layer.

Because `--no-includes` is in effect, your rule never sees the contents of headers it
`#include`s. Match what is written in the `.c` file, not what a macro expands to after
preprocessing.

## Learning from Existing Rules

The 500+ rules in `cvehound/cve/` are the real specification. Find ones like yours:

```bash
cd cvehound/cve

# By vulnerability type
grep -l "memset" *.cocci          # initialization bugs
grep -l "copy_to_user" *.cocci    # information leaks
grep -l "when != if" *.cocci      # missing checks

# By technique
grep -l 'depends on' *.cocci               # inter-rule dependencies
grep -l 'depends on .*&&' *.cocci          # conjunctions (several conditions)
grep -l '\\(' *.cocci                      # function alternatives
grep -w 'when forall' *.cocci              # ellipses pinned to all-paths

# The most involved rules, worth reading once
wc -l *.cocci | sort -n | tail -5
```

Around a fifth of the rules use `depends on`; reading a few of those is the fastest way to
learn when a dependency is warranted and when two independent starred rules are the right
answer.

## Examples Walkthrough

Every example below is quoted from the real file in `cvehound/cve/` — only Example 3 is
cut short, as noted there.

### Example 1: Simple Pattern - CVE-2015-4004

**Vulnerability**: Driver with unfixed initialization function

**Fix Commit**: Removed vulnerable driver entirely

**Strategy**: Detect presence of the removed driver initialization function

```cocci
/// Files: drivers/staging/ozwpan/ozmain.c
/// Fix: a73e99cb67e7438e5ab0c524ae63a8a27616c839
/// Detect-To: 62450bca861f206b09b44492b829b419222c4968

@err@
@@

* ozwpan_init(...)
{
	...
}
```

**Explanation**:
- Matches the entire `ozwpan_init` function
- If this function exists, the vulnerable driver is present
- The `*` sits on the function's signature line — one line, and it is the whole report
- Simple and effective for removed/deprecated code

### Example 2: Value-Based Detection - CVE-2020-12912

**Vulnerability**: Incorrect file permission in sysfs attribute

**Fix**: Changed `return 0444;` to `return 0400;`

**Strategy**: Detect the specific insecure return value

```cocci
/// Files: drivers/hwmon/amd_energy.c
/// Fix: 60268b0e8258fdea9a3c9f4b51e161c123571db3
/// Detect-To: 8abee9566b7e8eecf566c4daf6be062a27369890

@err@
@@

amd_energy_is_visible(...)
{
*	return 0444;
}
```

**Explanation**:
- Matches specific function `amd_energy_is_visible`
- Looks for exact vulnerable value `0444` (read for all)
- Fixed version returns `0400` (read for owner only)
- Context (function name) prevents false positives
- Nothing else in the rule: no metavariables, no dependencies, one starred line

### Example 3: Missing Initialization - CVE-2020-12352

**Vulnerability**: Uninitialized struct sent to Bluetooth device

**Fix**: Added `memset(&req, 0, sizeof(req));` before sending

**Strategy**: Detect struct usage without initialization

```cocci
/// Files: net/bluetooth/a2mp.c
/// Fix: eddb7732119d53400f48a02536a84c509692faa8
/// Detect-To: 6b44d9b8d96b37f72ccd7335b32f386a67b7f1f4

@err@
identifier v;
type T;
@@

	T v;
	... when != memset(&v, 0, sizeof(v));
*	a2mp_send(..., sizeof(v), &v);
```

**Explanation**:
- `T v;` anchors the match to a local declaration, so a parameter or a heap pointer
  passed to `a2mp_send` cannot match
- `when != memset(...)` ensures that declaration is NOT zeroed on the way
- `identifier v` ties the declaration, the `memset` and the `sizeof(v), &v` arguments to
  one variable
- This is the canonical Missing Fix Detection shape

The fix added a `memset` in front of ten different `a2mp_*` functions, and the rule used
to spell out all ten — one rule per function, each naming its function, its struct type
and its `A2MP_*` command. That is the shape to avoid. All ten sites share one invariant,
one rule states it, and the collapsed rule reports exactly the same lines while requiring
a single token (`a2mp_send`) instead of twenty-six. There is no function wrapper either:
`...` never crosses a function boundary, so the enclosing `f(...) { ... }` bought nothing.
See [Rule 8](#rule-8-keep-the-grep-query-selective).

### Example 4: Complex Dependencies - CVE-2016-5195 (Dirty COW)

**Vulnerability**: Copy-on-write race condition

**Fix**: Multiple changes across memory management

**Strategy**: Check for new function and missing fixes

```cocci
/// Files: mm/gup.c mm/memory.c mm/madvise.c
/// Fix: 19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619
/// Detect-To: 0a27a14a62921b438bb6f33772690d345a089be6

@madvise@
@@

madvise_need_mmap_write(...)
{
	...
}

@err_follow_page_pte depends on madvise@
identifier flags;
statement S;
@@

\(follow_page_pte\|follow_page_mask\|follow_page\)(...)
{
	... when any
*	if ((flags & FOLL_WRITE) && !pte_write(...)) S
	... when any
}

@err_faultin_page depends on madvise@
identifier flags;
@@

\(faultin_page\|__get_user_pages\|get_user_pages\)(...)
{
	... when any
*	*flags &= ~FOLL_WRITE;
	... when any
}
```

**Explanation**:
- First rule checks whether the fix introduced `madvise_need_mmap_write`; it does **not**
  star anything, because it is a guard, not the report
- Only checks for unfixed patterns if this function exists (`depends on madvise`)
- Uses function alternatives with `\(func1\|func2\|func3\)` for renamed variants
- Two independent starred rules: either site reports on its own (an OR)

### Example 5: ASLR Weakness - CVE-2015-1593

**Vulnerability**: Weak stack randomization

**Fix**: Removed function that reduced randomization entropy

**Strategy**: Detect presence of weak randomization function

```cocci
/// Files: arch/x86/mm/mmap.c fs/binfmt_elf.c
/// Fix: 4e7c22d447bb6d7e37bfe39ff658486ae78e8d77
/// Fixes: v2.6.12-rc2

@err_stack_maxrandom_size@
@@

* unsigned int stack_maxrandom_size(void)
{
	...
}

@err_randomize_stack_top@
identifier random_variable;
@@

	unsigned int random_variable = 0;
	...
(
*	random_variable = get_random_int() % ...;
|
*	random_variable = get_random_int() & ...;
)
```

**Explanation**:
- Detects the vulnerable `stack_maxrandom_size` function
- Also detects weak randomization pattern in `randomize_stack_top`
- Uses disjunction `( ... | ... )` for alternative operations (% or &) — the star goes
  inside each branch, on the assignment that identifies the bug, not on the declaration
  above it
- Both patterns indicate the vulnerable code is present, and either reports alone

## Troubleshooting

### Problem: Pattern doesn't match

**Solutions**:
- Simplify pattern - remove unnecessary details
- Check for whitespace/formatting differences
- Test with `--debug` flag: `spatch --debug file.c`
- Use `...` to skip over irrelevant code

### Problem: Rule parses and matches but prints nothing

**Solutions**:
- Check that something is starred — without a `*` there is no report
- Check that no starred line is a lone `}` — spatch drops that star silently, so the
  branch it sits in matches without reporting (see
  [Rule 2](#rule-2-star-discipline))
- Check that the `*` is in the rule that actually matched, not only in a rule whose
  `depends on` was not satisfied
- Make sure you did not pass `--no-show-diff`; it suppresses the diff, which is the report

### Problem: Too many false positives

**Solutions**:
- Add more context (function name, surrounding code)
- Use `when !=` constraints
- Make the pattern more specific
- Add dependencies on other rules
- Check if fix actually addresses your pattern

### Problem: The rule exceeds its time budget

`check_cve()` runs spatch under two bounds, and blowing either one fails the CVE with
`SpatchTimeout` — a rule that gives up mid-scan cannot be told apart from one that found
nothing, so it is reported rather than silently returning "not vulnerable".

| Bound | Value | Counts | Covers |
| --- | --- | --- | --- |
| `--timeout` (`SPATCH_TIMEOUT`) | 60 | CPU-seconds, per work unit | the matching engine only |
| wall watchdog (`SPATCH_WALL_TIMEOUT`) | 300 | wall seconds, per invocation | the whole run |

Two things about `--timeout` are easy to get wrong. It counts **CPU** time
(coccinelle arms `ITIMER_VIRTUAL`), not wall time, so a machine that is merely
oversubscribed does not trip it. That is not the same as being load-proof: work
competing for cache and memory bandwidth bills more CPU for the same result, and the
sweep below moved by more than 2x between an idle machine and one running the suite.
And its unit is a *work unit*, not a file: given a list of files spatch treats the
whole list as one, and only a directory argument (`--all-files`) is split per file.

Either bound says the same thing about a rule that hits it, and both are set well
above what the tree actually costs: the slowest whole-tree scan takes 43s against the
300s wall bound, and the most expensive single file needs 0.5 CPU-seconds of engine
time against the 60 CPU-second one. The margin is for the two things that move that
number — machine load and core speed, both of which scale billed CPU — not for
expensive rules. Hitting either means the pattern, not the machine. The usual cause is a
`<+... ...+>` wrapped around a statement body where `... when any` would do — same
question asked, ~40x the cost (see
[Rule 8](#rule-8-keep-the-grep-query-selective) and the note under
[Restricting a Pattern to Particular Functions](#restricting-a-pattern-to-particular-functions)). `--profile`
names the phase: time in `full_engine` with little in `mysat` is parsing, not matching.

The failure looks different depending on how spatch was invoked, which is why cvehound
classifies on stderr rather than the exit code:

```
timeout (we abort): <files>                  # file list: exit 2, run aborts
Fatal error: exception ...Common.Timeout
EXN: ...Common.Timeout in <file>             # directory: exit 0, that file dropped
```

`validate-rule.sh` runs with the same `--timeout`, so a rule over budget is caught before
it reaches the suite.

### Problem: Coccinelle crashes or hangs

**Solutions**:
- Reduce scope with file-specific matching
- Avoid deeply nested `...` patterns
- Split complex rules into smaller ones
- Check which `spatch` you are running: the function-definition wrapper shape was
  pathological before the `satLabel` fix (see the footnote under
  [Restricting a Pattern to Particular Functions](#restricting-a-pattern-to-particular-functions))

### Problem: The rule is slow on a whole-tree scan

Almost always this is the prefilter, not the matching: spatch is parsing files it should
have skipped. Count them with the command in
[Rule 8](#rule-8-keep-the-grep-query-selective) before touching the pattern — if it is
not zero, fix the required constants rather than the CTL. `--profile` settles it either
way: `full_engine` far above `mysat` means the time went into parsing C, not model
checking.

### Problem: The rule fires on a fixed tree

**Solutions**:
- Look at which lines the diff removed — that names the rule that fired
- Check that no helper rule stars anything; a starred `@fix@`-style rule reports whenever
  it matches, whatever the rest of the file says
- Check that a multi-line starred pattern is not reporting a partial match: star only the
  identifying line
- Check the `depends on` chain: a condition you meant as an AND is an OR unless the last
  rule depends on the earlier ones

### Problem: Rule works in one kernel version but not another

**Solutions**:
- Check if affected code exists in that version
- If the pattern spells out the code's exact shape, rewrite it around the invariant —
  the anchor that existed for the whole range plus a `depends on !fixed` helper — rather
  than adding another disjunction branch per era (see
  [Rule 7](#rule-7-match-the-invariant-not-the-era))
- Check the starred line in *that* version: a star on a token the older code builds by
  macro expansion aborts spatch ("try to delete an expanded token"), and a star on a
  lone `}` is silently dropped (see [Rule 2](#rule-2-star-discipline))
- Account for backported changes
- Use alternative patterns with `\( ... \| ... \)` for renamed functions
- Consider using version-specific metadata

### Problem: Macro expansion issues

**Solutions**:
- "try to delete an expanded token: X" (exit 255) means a `*` sits on a token that this
  version of the code produces via a macro (`ECALL(...)`-style wrappers are common in
  2.6-era drivers). Context lines may match expanded code; starred lines may not. Move
  the star to an adjacent plain-token statement.
- Match both macro and expanded forms
- Remember CVEhound runs with `--no-includes`, so headers are not resolved
- Use `--macro-file` option with spatch when testing manually
- Test with actual kernel build system

### Getting Help

1. **Coccinelle Documentation**: https://coccinelle.gitlabpages.inria.fr/website/docs/
2. **Coccinelle Mailing List**: cocci@inria.fr
3. **CVEhound Issues**: https://github.com/linux-analysis/cvehound/issues
4. **Existing Rules**: Study similar CVE rules in `cvehound/cve/`
5. **Test Suite**: See `tests/` for working examples

## Additional Resources

### Coccinelle Documentation
- [Coccinelle Tutorial](https://coccinelle.gitlabpages.inria.fr/website/docs/main_grammar.html)
- [Semantic Patch Language Reference](https://coccinelle.gitlabpages.inria.fr/website/docs/main_grammar.html)
- [Coccinelle Examples](https://github.com/coccinelle/coccinelle/tree/master/demos)

### Linux Kernel Resources
- [kernel.org vulns.git](https://git.kernel.org/pub/scm/linux/security/vulns.git/)
- [CIP kernel-sec](https://gitlab.com/cip-project/cip-kernel/cip-kernel-sec)
- [Kernel Git Repository](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git)
- [LWN Kernel Coverage](https://lwn.net/Kernel/)

### CVEhound Resources
- [CVEhound Repository](https://github.com/linux-analysis/cvehound)
- [Existing Rules](../cvehound/cve/)
- [Rule Template](../contrib/template.cocci)
- [Blank Template](../contrib/blank.cocci)

## Contributing

When contributing new CVE detection rules:

1. Follow the naming convention: `CVE-YYYY-NNNNN.cocci` — uppercase `CVE`, four-digit
   year, no prefix or suffix. `cve-2020-12912.cocci`, `CVE-2020-12912.patch`, and
   `rule_CVE-2020-12912.cocci` are all wrong.
2. Place the file in `cvehound/cve/` (or `cvehound/cve/disputed/` for disputed CVEs —
   note those are skipped by the default `--cve assigned`)
3. Include complete metadata (`Files:`, `Fix:`, and one of `Fixes:`/`Detect-To:`)
4. Run `uv run pytest --runslow --cve=CVE-YYYY-NNNNN` — the suite picks the rule up
   automatically; don't add test functions
5. Submit a pull request with a clear description
6. Reference CVE sources and fix commits

## License

All CVE detection rules in CVEhound are licensed under GPLv2, following the Linux kernel license.
