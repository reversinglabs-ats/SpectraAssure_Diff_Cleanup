# spectra-assure-diff-cleanup

Reduce noise in Spectra Assure `rl-diff` JSON reports so only meaningful changes
remain. A minor version bump can produce hundreds of diff entries that are just
file moves, renames, and routine content updates with no security relevance. This
tool keeps an entry only when it carries real signal — a policy violation, a
warning, or a change to the file's behavior, install actions, threat indicators,
or classification — and drops the rest.

In testing against a real HP SureClick Enterprise minor bump, this reduced 629
diff entries to the 3 that actually mattered.

It works on both the JSON report and the interactive `rl-html` report — the same
filter, applied to the HTML report's embedded diff data, so the "Version Diff"
view opens already decluttered.

## Disclaimer of Warranty

This application is provided "as is" and "as available" without any warranties of any kind, either express or implied.

Reversing Labs make no representations or warranties of any kind, including but not limited to:

- The accuracy, completeness, or timeliness of the information submitted or received via this application;
- The functionality, availability, or performance of the application;
- The security, integrity, or confidentiality of submitted files or user data; or
- The fitness of this application for any particular purpose.

Use of this application is at your own risk. By using this application, you acknowledge that any data submitted to third-party services (e.g., ReversingLabs Spectra Analyze) may be subject to their own terms and conditions.

In no event shall the developer be liable for any direct, indirect, incidental, special, exemplary, or consequential damages arising out of or in any way connected with the use or misuse of this application.

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

The tool takes one `rl-diff` JSON report in and writes a cleaned copy out, with
the noise entries removed. Everything else about the report is preserved.

### 1. Generate an `rl-diff` report

Produce the report with the Spectra Assure CLI (`rl-secure`):

```bash
rl-secure report rl-diff pkg:rl/<project>/<package>@<new> \
  --diff-with=<old> --output-path .
```

This writes `report.rl-diff-diff-with-<old>.json` to the current directory.

### 2. Clean it

Run the tool on that report. After `pip install` you can use either the
`diff-cleanup` console command or `python -m diff_cleanup` — they are identical:

```bash
diff-cleanup report.rl-diff-diff-with-<old>.json -o cleaned.json
# or
python -m diff_cleanup report.rl-diff-diff-with-<old>.json -o cleaned.json
```

`cleaned.json` is the same report structure with the noise entries dropped from
`report.diff`.

### Arguments

| Argument | Meaning | Default |
|----------|---------|---------|
| `input` (positional) | Path to the `rl-diff` JSON report, **or** an `rl-html` report directory, to clean | read from **stdin** (JSON) |
| `-o`, `--output` | Path to write the cleaned report (file for JSON; **required** output directory for `rl-html`) | write to **stdout** (JSON) |
| `-c`, `--config` | Alternate allow/deny TOML for this run (see below) | bundled config |
| `--explain` | Print one line per suppressed entry to stderr showing why it was dropped | off |

### Input and output

Because input defaults to stdin and output to stdout, the tool composes in a
pipeline:

```bash
cat report.rl-diff-diff-with-1.0.1.json | diff-cleanup > cleaned.json
```

Mix and match freely — read a file, write to stdout:

```bash
diff-cleanup report.rl-diff-diff-with-1.0.1.json | jq '.report.diff | length'
```

A one-line summary (`kept N / M entries (K suppressed)`) is written to **stderr**,
so it never pollutes the JSON on stdout. On a bad input (missing file, invalid
JSON, or a file that isn't an `rl-diff` report) the tool prints
`diff_cleanup: <reason>` to stderr and exits non-zero.

### How it decides

An entry is suppressed only when it has no violations, no warnings, and every
change category it reports is *denied* (structural noise). Anything else —
including a change category the tool hasn't seen before — is kept. The tool errs
toward surfacing.

By default the denied categories are `hash`, `name`, `size`, `entropy`, and `functionality`.

To see exactly why each entry was suppressed, pass `--explain`:

```bash
diff-cleanup report.json --explain -o cleaned.json
# stderr output (one line per suppressed entry):
# suppressed  %InstallDir%/4.4.32.159/BrService.exe  [hash, name, size]
# suppressed  %InstallDir%/4.4.32.159/BrChrome.dll   [functionality, hash, name, size]
# ...
# kept 3 / 629 entries (626 suppressed)
```

`--explain` writes to stderr so it doesn't interfere with the JSON on stdout or
in `-o`. It can be combined with any other flags.

### Configuring which changes are noise

Which categories count as noise (`deny`) versus signal (`allow`) lives in a TOML
config that the tool reads **automatically** — no flag needed. It ships at
`src/diff_cleanup/default_config.toml` as a `[changes]` table mapping each
category to `"deny"` or `"allow"`:

```toml
[changes]
hash = "deny"
name = "deny"
size = "deny"
entropy = "deny"
tag  = "allow"
# ...
```

Edit that file to change behavior. With an editable install (`pip install -e .`)
the package points at the source tree, so your edits take effect directly.

A category not listed is treated as `allow` (kept), so a brand-new category is
never silently dropped. Violations and warnings always keep an entry regardless
of the table.

To try an alternate ruleset without touching the bundled file, point `--config`
at your own copy for that run:

```bash
diff-cleanup report.json --config my-rules.toml -o cleaned.json
```

### Cleaning an `rl-html` report

`rl-secure` can also emit an interactive HTML report. Use the `rl-html` report
type with `--diff-with` to get a version diff:

```bash
rl-secure report rl-html pkg:rl/<project>/<package>@<new> \
  --diff-with=<old> --output-path ./html-report
```

That writes a directory (an `*sdlc.html` file plus a `__deps/` folder). Point the
tool at the directory and give it an output directory with `-o`:

```bash
diff-cleanup ./html-report -o ./html-report-clean
```

The tool copies the report to the output directory and filters the diff embedded
in it, so the "Version Diff" view shows only the signal entries. The full report
data is untouched — only the diff list is reduced, and nothing else about the
report changes. `--config` and `--explain` work the same as for JSON.

The output directory must not already exist (the tool will not overwrite one), and
`-o` is required here — an HTML report is a directory, not something to stream to
stdout.

## Development

```bash
ruff check .              # lint
ruff format --check .     # format check
mypy src tests            # type check
pytest                    # test
```

## License

MIT — see [LICENSE](LICENSE).
