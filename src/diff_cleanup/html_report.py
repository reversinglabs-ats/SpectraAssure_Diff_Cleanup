"""Apply the same noise filter to an ``rl-html`` diff report.

The HTML report is a React single-page app. ``sdlc.html`` boots it; the data
lives in ``__deps/data.js`` as three byte arrays serialized as JS integer lists:
``reportData`` (the full report), ``diffData`` (the version diff), and
``checksData``. Each is a small magic header plus a MessagePack document.

Only ``diffData`` drives the "Version Diff" view. It decodes to a 12-element
list whose element ``[7]`` is the per-file change list — the same entries as the
``rl-diff`` JSON, just positional. So the existing :func:`is_signal` rule applies
unchanged; we drop the noise entries, fix the three file counters the summary
reads, and write the array back. ``reportData`` is left intact, so nothing is
lost — only the diff table is decluttered.

The positional layouts below come from the report's own deserializer
(``changeDiff`` / ``fileChange`` / ``fileBasicObject`` in ``webworker.js``).
"""

from pathlib import Path

from diff_cleanup import DEFAULT_DENY_KEYS, _strip_paired_actions, is_signal
from diff_cleanup import _msgpack as msgpack

# diffData magic header: b"DIFF" + a little-endian uint32 format version.
# The positional layouts below were reverse-engineered from the report's own
# deserializer at one format version; a different version may reorder fields, so
# we refuse to edit anything we have not validated against (see decode_blob).
_MAGIC = b"DIFF"
_HEADER_LEN = 8
_SUPPORTED_VERSION = 5

# Top-level changeDiff list[12] — only the fields we touch are named.
_FILES_CHANGED, _FILES_ADDED, _FILES_REMOVED = 3, 4, 5
_FILES = 7
_DIFF_LEN = 12

# A file entry is list[5]: [file, uuid, violations, warnings, changes].
_FILE, _UUID, _VIOLATIONS, _WARNINGS, _CHANGES = range(5)
# A diffChange is list[4]: [change, previous, current, tags].
_CHANGE, _PREVIOUS, _CURRENT = 0, 1, 2
# A file basic object is list[12]; we only read name/alias/path for --explain.
_NAME, _ALIAS, _PATH = 2, 3, 4


def _entry_is_signal(entry: list, deny_keys: frozenset[str]) -> bool:
    return is_signal(
        {
            "violations": entry[_VIOLATIONS],
            "warnings": entry[_WARNINGS],
            "changes": entry[_CHANGES],
        },
        deny_keys,
    )


def _change_kind(entry: list) -> str:
    # The UI derives a row's kind from its hash change, defaulting to "changed"
    # when there is none (e.g. a classification-only change).
    hash_changes = entry[_CHANGES].get("hash")
    if hash_changes:
        return hash_changes[0][_CHANGE]
    return "changed"


def _strip_actions(entry: list) -> list:
    """Drop version/GUID-paired registry actions from a kept entry, like the JSON path.

    Reuses :func:`_strip_paired_actions`, which works on dicts, by tagging each
    positional action's dict with its index and reading the surviving indices
    back. Carrying the index in the data (rather than matching by ``id()``) keeps
    this correct even if the helper ever returns copies instead of the originals.
    """
    actions = entry[_CHANGES].get("action")
    if not actions:
        return entry
    as_dicts = [
        {"_idx": i, "change": a[_CHANGE], "previous": a[_PREVIOUS], "current": a[_CURRENT]}
        for i, a in enumerate(actions)
    ]
    kept_idx = {d["_idx"] for d in _strip_paired_actions(as_dicts)}
    if len(kept_idx) == len(actions):
        return entry
    stripped = [a for i, a in enumerate(actions) if i in kept_idx]
    new_entry = list(entry)
    new_entry[_CHANGES] = {**entry[_CHANGES], "action": stripped}
    return new_entry


def filter_diff(diff: list, deny_keys: frozenset[str] = DEFAULT_DENY_KEYS) -> tuple[list, int, int]:
    """Return ``(new_diff, kept, suppressed)`` for a decoded diffData document.

    The input is not modified. The three file counters are recomputed from the
    kept entries so the summary view stays consistent with the table.
    """
    if not isinstance(diff, list) or len(diff) != _DIFF_LEN:
        raise ValueError("not a diffData document")

    kept = [_strip_actions(e) for e in diff[_FILES] if _entry_is_signal(e, deny_keys)]

    new_diff = list(diff)
    new_diff[_FILES] = kept
    new_diff[_FILES_CHANGED] = sum(1 for e in kept if _change_kind(e) == "changed")
    new_diff[_FILES_ADDED] = sum(1 for e in kept if _change_kind(e) == "added")
    new_diff[_FILES_REMOVED] = sum(1 for e in kept if _change_kind(e) == "removed")
    return new_diff, len(kept), len(diff[_FILES]) - len(kept)


def suppressed_entries(diff: list, deny_keys: frozenset[str] = DEFAULT_DENY_KEYS) -> list[list]:
    """Return the file entries that :func:`filter_diff` would drop (for --explain)."""
    return [e for e in diff[_FILES] if not _entry_is_signal(e, deny_keys)]


def entry_path(entry: list) -> str:
    file = entry[_FILE]
    return file[_PATH] or file[_ALIAS] or file[_NAME] or "<unknown>"


def decode_blob(blob: bytes) -> tuple[bytes, list]:
    if blob[:4] != _MAGIC:
        raise ValueError(f"not a diffData blob (magic {blob[:4]!r})")
    version = int.from_bytes(blob[4:_HEADER_LEN], "little")
    if version != _SUPPORTED_VERSION:
        raise ValueError(
            f"unsupported diffData format version {version} "
            f"(this tool was built for version {_SUPPORTED_VERSION}); the report "
            "layout may have changed, so refusing to edit it rather than risk corruption"
        )
    doc = msgpack.unpackb(blob[_HEADER_LEN:])
    if not isinstance(doc, list):
        raise ValueError("diffData payload is not a list")
    return blob[:_HEADER_LEN], doc


def encode_blob(header: bytes, diff: list) -> bytes:
    return header + msgpack.packb(diff)


def _array_span(text: str, name: str) -> tuple[int, int]:
    marker = name + ":["
    start = text.find(marker)
    if start == -1:
        raise ValueError(f"{name} not found in data.js")
    start += len(marker)
    end = text.find("]", start)
    if end == -1:
        raise ValueError(f"{name} array is not terminated")
    return start, end


def read_blob(text: str, name: str) -> bytes:
    start, end = _array_span(text, name)
    return bytes(int(x) for x in text[start:end].split(","))


def replace_blob(text: str, name: str, blob: bytes) -> str:
    start, end = _array_span(text, name)
    return text[:start] + ",".join(map(str, blob)) + text[end:]


def clean_data_js(text: str, deny_keys: frozenset[str] = DEFAULT_DENY_KEYS) -> tuple[str, int, int]:
    """Filter the diffData blob inside a ``data.js`` text and splice it back in.

    Pure string transform: returns ``(new_text, kept, suppressed)``.
    """
    header, diff = decode_blob(read_blob(text, "diffData"))
    new_diff, kept, suppressed = filter_diff(diff, deny_keys)
    return replace_blob(text, "diffData", encode_blob(header, new_diff)), kept, suppressed


def clean_html_report(
    report_dir: str | Path, deny_keys: frozenset[str] = DEFAULT_DENY_KEYS
) -> tuple[int, int]:
    """Rewrite ``<report_dir>/__deps/data.js`` in place. Returns ``(kept, suppressed)``."""
    data_js = Path(report_dir) / "__deps" / "data.js"
    new_text, kept, suppressed = clean_data_js(data_js.read_text(encoding="latin-1"), deny_keys)
    data_js.write_text(new_text, encoding="latin-1")
    return kept, suppressed
