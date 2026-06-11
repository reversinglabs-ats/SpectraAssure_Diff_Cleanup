"""CLI: read an ``rl-diff`` JSON report, write a noise-reduced copy."""

import argparse
import json
import sys

from diff_cleanup import DEFAULT_DENY_KEYS, clean_report, is_signal, load_deny_keys


def _load(path: str | None) -> dict:
    if path:
        with open(path) as f:
            return json.load(f)
    return json.load(sys.stdin)


def _dump(report: dict, path: str | None) -> None:
    if path:
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
    else:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="diff_cleanup",
        description="Suppress noise in a Spectra Assure rl-diff JSON report.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Path to the rl-diff JSON report (default: stdin).",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Where to write the cleaned report (default: stdout).",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Override the bundled allow/deny TOML with an alternate config file.",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Print the change keys for each suppressed entry to stderr.",
    )
    args = parser.parse_args(argv)

    try:
        deny_keys = load_deny_keys(args.config) if args.config else DEFAULT_DENY_KEYS
        report = _load(args.input)
        cleaned, kept, suppressed = clean_report(report, deny_keys)
    except (OSError, json.JSONDecodeError, ValueError) as err:
        print(f"diff_cleanup: {err}", file=sys.stderr)
        return 1

    if args.explain:
        for e in report["report"]["diff"]:
            if not is_signal(e, deny_keys):
                path = e.get("file", {}).get("path") or e.get("file", {}).get("name", "<unknown>")
                keys = ", ".join(sorted(e.get("changes", {})))
                print(f"suppressed  {path}  [{keys}]", file=sys.stderr)

    _dump(cleaned, args.output)
    print(
        f"kept {kept} / {kept + suppressed} entries ({suppressed} suppressed)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
