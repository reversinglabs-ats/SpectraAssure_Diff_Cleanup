"""Suppress noise in Spectra Assure ``rl-diff`` JSON reports.

An ``rl-diff`` report lists one entry per changed file. Each entry records which
*categories* changed under ``changes``. A minor version bump produces hundreds of
entries whose only changes are structural — the bytes, path, or size differ — with
no change to how the file behaves or how it is classified. Those are noise.

The filter is deliberately conservative: an entry is kept unless it can be shown
to be pure noise. Any change category outside the *denied* set — including one we
have never seen — keeps the entry, as does any violation or warning.

Which categories are denied (structural noise) versus allowed (signal) is data,
not code: it lives in ``default_config.toml`` next to this module, which is loaded
automatically into :data:`DEFAULT_DENY_KEYS`. Edit that file to change behavior; no
flag required. :func:`load_deny_keys` parses an alternate config when one is given.
"""

import tomllib
from pathlib import Path

DEFAULT_CONFIG_PATH = Path(__file__).with_name("default_config.toml")


def load_deny_keys(path: str | Path) -> frozenset[str]:
    """Read a TOML config and return the set of denied change categories.

    The config's ``[changes]`` table maps each category to ``"deny"`` or
    ``"allow"``. Only the ``"deny"`` keys are returned; every other category —
    ``"allow"`` ones and any not listed — is treated as signal by
    :func:`is_signal`.

    Raises ``ValueError`` if a value is anything other than ``"deny"`` or
    ``"allow"``.
    """
    with open(path, "rb") as f:
        config = tomllib.load(f)

    changes = config.get("changes", {})
    deny: set[str] = set()
    for key, value in changes.items():
        if value not in ("deny", "allow"):
            raise ValueError(f"changes.{key} must be 'deny' or 'allow', got {value!r}")
        if value == "deny":
            deny.add(key)
    return frozenset(deny)


# Loaded from the bundled TOML at import so the config file is the single source
# of truth. Out of the box this is {hash, name, size, entropy} — byte/path/size
# churn that adds no security signal. (``entropy`` is byte-derived, so it tracks
# hash/size; a 2026-06-10 crawl found 1499 entries of pure structural+entropy
# churn.) An editable install points at the source tree, so editing
# ``default_config.toml`` there takes effect directly.
DEFAULT_DENY_KEYS = load_deny_keys(DEFAULT_CONFIG_PATH)

# Backwards-compatible alias for the previous name.
STRUCTURAL_CHANGE_KEYS = DEFAULT_DENY_KEYS


def is_signal(entry: dict, deny_keys: frozenset[str] = DEFAULT_DENY_KEYS) -> bool:
    """Return True if a diff entry is worth surfacing.

    Kept unless provably noise: a violation, a warning, or any change category
    outside ``deny_keys`` makes an entry signal.
    """
    if entry.get("violations") or entry.get("warnings"):
        return True
    non_denied = set(entry.get("changes", {})) - deny_keys
    return bool(non_denied)


def clean_report(
    report: dict, deny_keys: frozenset[str] = DEFAULT_DENY_KEYS
) -> tuple[dict, int, int]:
    """Filter ``report.diff`` down to signal entries.

    Returns ``(cleaned_report, kept, suppressed)``. The cleaned report is the same
    structure with a reduced diff list; the input is not modified.

    Raises ``ValueError`` if the input is not an ``rl-diff`` report.
    """
    diff = report.get("report", {}).get("diff")
    if diff is None:
        raise ValueError("not an rl-diff report: missing report.diff")

    kept = [entry for entry in diff if is_signal(entry, deny_keys)]

    cleaned = dict(report)
    cleaned["report"] = dict(report["report"])
    cleaned["report"]["diff"] = kept
    return cleaned, len(kept), len(diff) - len(kept)
