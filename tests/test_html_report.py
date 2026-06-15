import shutil
from pathlib import Path

import pytest

from diff_cleanup import _msgpack as msgpack
from diff_cleanup.__main__ import main
from diff_cleanup.html_report import (
    clean_data_js,
    clean_html_report,
    decode_blob,
    encode_blob,
    filter_diff,
    read_blob,
    replace_blob,
)

DATA = Path(__file__).parent / "data"
HTML_DATA_JS = DATA / "rl-html-diff-with-4.4.32.159" / "__deps" / "data.js"


# --- vendored msgpack codec -------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        0,
        127,
        128,
        255,
        256,
        65535,
        65536,
        2**32 - 1,
        2**32,
        2**64 - 1,
        -1,
        -32,
        -33,
        -128,
        -129,
        -32768,
        -(2**31),
        -(2**63),
        3.14159,
        -2.5,
        0.0,
        "",
        "x" * 31,
        "y" * 32,
        "z" * 256,
        "u" * 70000,
        "snowman ☃",
        b"",
        b"\x00\x01\x02",
        b"q" * 300,
        [],
        [1, [2, [3, [4]]]],
        {},
        {"a": 1, "b": [True, None, "c"]},
        {"k" * 40: "v" * 40},
        list(range(20)),
    ],
)
def test_msgpack_round_trip(value):
    assert msgpack.unpackb(msgpack.packb(value)) == value


def test_msgpack_rejects_trailing_bytes():
    with pytest.raises(msgpack.MsgpackError):
        msgpack.unpackb(msgpack.packb(1) + b"\x01")


def test_msgpack_rejects_unencodable():
    with pytest.raises(msgpack.MsgpackError):
        msgpack.packb({1, 2, 3})


def test_msgpack_str_with_invalid_utf8_round_trips():
    # A fixstr (0xA2, len 2) whose payload is not valid UTF-8. Decoding must not
    # crash, and re-encoding must reproduce the original bytes exactly.
    blob = b"\xa2\xff\xfe"
    assert msgpack.packb(msgpack.unpackb(blob)) == blob


# --- diff blob fixtures -----------------------------------------------------


def file_obj(name="f.dll", path="/p/f.dll"):
    # [unnamed, deleted, name, alias, path, category, type, subtype, format, version, size, hashes]
    return [False, False, name, "", path, "other", "Binary", "", "", "", 100, []]


def change(kind="changed", previous="a", current="b"):
    return [kind, previous, current, []]


def entry(uuid="u", changes=None, violations=None, warnings=None, name="f.dll", path="/p/f.dll"):
    # [file, uuid, violations, warnings, changes]
    return [file_obj(name, path), uuid, violations or [], warnings or [], changes or {}]


def diff_doc(entries):
    # changeDiff list[12]; the three counters start wrong on purpose so we can
    # prove filter_diff recomputes them.
    return ["pass", "repro-not-checked", file_obj(), 999, 999, 999, 0, list(entries), 0, 0, 0, {}]


def diff_blob(entries):
    return b"DIFF" + (5).to_bytes(4, "little") + msgpack.packb(diff_doc(entries))


# --- filter_diff ------------------------------------------------------------


def test_filter_drops_structural_only():
    doc = diff_doc(
        [
            entry("noise", {"hash": [change()], "name": [change()], "size": [change()]}),
            entry("signal", {"hash": [change()], "indicator": [change()]}),
        ]
    )
    new_doc, kept, suppressed = filter_diff(doc)
    assert (kept, suppressed) == (1, 1)
    assert [e[1] for e in new_doc[7]] == ["signal"]


def test_filter_recomputes_counts():
    doc = diff_doc(
        [
            entry("c", {"hash": [change("changed")], "tag": [change()]}),
            entry("a", {"hash": [change("added", "", "x")]}),  # added + only hash -> noise
            entry("a2", {"hash": [change("added", "", "x")], "indicator": [change()]}),
            entry("r", {"hash": [change("removed", "x", "")], "tag": [change()]}),
        ]
    )
    new_doc, kept, suppressed = filter_diff(doc)
    assert kept == 3 and suppressed == 1
    assert (new_doc[3], new_doc[4], new_doc[5]) == (1, 1, 1)  # changed, added, removed


def test_filter_keeps_on_violation_or_warning():
    doc = diff_doc(
        [
            entry("v", {"hash": [change()]}, violations=[{"id": "SQ1"}]),
            entry("w", {"name": [change()]}, warnings=["heads up"]),
        ]
    )
    _, kept, suppressed = filter_diff(doc)
    assert (kept, suppressed) == (2, 0)


def test_filter_does_not_mutate_input():
    doc = diff_doc([entry("noise", {"hash": [change()]})])
    filter_diff(doc)
    assert len(doc[7]) == 1
    assert (doc[3], doc[4], doc[5]) == (999, 999, 999)


def test_filter_strips_paired_actions_in_kept_entry():
    actions = [
        change("removed", "key=HKCR\\Bromium_4.4.32.159", ""),
        change("added", "", "key=HKCR\\Bromium_4.4.32.162"),
        change("removed", "key=HKCR\\OnlyOld", ""),
    ]
    doc = diff_doc([entry("sig", {"action": actions})])
    new_doc, kept, _ = filter_diff(doc)
    assert kept == 1
    result = new_doc[7][0][4]["action"]
    assert len(result) == 1
    assert result[0][1] == "key=HKCR\\OnlyOld"


def test_filter_strips_balanced_duplicate_action_pairs():
    # Two identical removed/added version pairs (same normalized form) plus one
    # genuinely-removed action. Index-based mapping must drop all four paired
    # items and keep only the unpaired one, regardless of value duplication.
    actions = [
        change("removed", "key=App_4.4.32.159", ""),
        change("removed", "key=App_4.4.32.159", ""),
        change("added", "", "key=App_4.4.32.162"),
        change("added", "", "key=App_4.4.32.162"),
        change("removed", "key=GoneForGood", ""),
    ]
    doc = diff_doc([entry("sig", {"action": actions})])
    new_doc, kept, _ = filter_diff(doc)
    assert kept == 1
    result = new_doc[7][0][4]["action"]
    assert [a[1] for a in result] == ["key=GoneForGood"]


def test_filter_rejects_non_diff_document():
    with pytest.raises(ValueError):
        filter_diff([1, 2, 3])


# --- blob + data.js plumbing ------------------------------------------------


def test_decode_rejects_bad_magic():
    with pytest.raises(ValueError):
        decode_blob(b"XXXX" + b"\x00" * 4 + msgpack.packb(diff_doc([])))


def test_decode_rejects_unsupported_version():
    blob = b"DIFF" + (6).to_bytes(4, "little") + msgpack.packb(diff_doc([]))
    with pytest.raises(ValueError, match="unsupported diffData format version 6"):
        decode_blob(blob)


def test_encode_decode_round_trip():
    header, doc = decode_blob(diff_blob([entry("x", {"tag": [change()]})]))
    assert header == b"DIFF" + (5).to_bytes(4, "little")
    assert encode_blob(header, doc) == diff_blob([entry("x", {"tag": [change()]})])


def data_js_text(entries, report=(1, 2, 3), checks=(9, 9)):
    blob = diff_blob(entries)
    return (
        "head;"
        f"reportData:[{','.join(map(str, report))}];"
        f"diffData:[{','.join(map(str, blob))}];"
        f"checksData:[{','.join(map(str, checks))}];tail"
    )


def test_clean_data_js_filters_and_preserves_siblings():
    text = data_js_text(
        [
            entry("noise", {"hash": [change()], "size": [change()]}),
            entry("signal", {"tag": [change()]}),
        ]
    )
    new_text, kept, suppressed = clean_data_js(text)
    assert (kept, suppressed) == (1, 1)
    # the other two blobs are untouched
    assert "reportData:[1,2,3]" in new_text
    assert "checksData:[9,9]" in new_text
    _, doc = decode_blob(read_blob(new_text, "diffData"))
    assert [e[1] for e in doc[7]] == ["signal"]


def test_read_blob_missing_name():
    with pytest.raises(ValueError):
        read_blob("nothing here", "diffData")


def test_replace_blob_is_reversible():
    text = data_js_text([entry("x", {"tag": [change()]})])
    blob = read_blob(text, "diffData")
    assert read_blob(replace_blob(text, "diffData", blob), "diffData") == blob


# --- CLI integration --------------------------------------------------------


def write_report(dir_path, entries):
    deps = dir_path / "__deps"
    deps.mkdir(parents=True)
    (dir_path / "sdlc.html").write_text("<html></html>")
    (deps / "data.js").write_text(data_js_text(entries), encoding="latin-1")
    return dir_path


def test_cli_directory_input_filters(tmp_path):
    src = write_report(
        tmp_path / "rep",
        [entry("noise", {"hash": [change()]}), entry("signal", {"indicator": [change()]})],
    )
    out = tmp_path / "out"
    assert main([str(src), "-o", str(out)]) == 0
    text = (out / "__deps" / "data.js").read_text(encoding="latin-1")
    _, doc = decode_blob(read_blob(text, "diffData"))
    assert [e[1] for e in doc[7]] == ["signal"]


def test_cli_directory_requires_output(tmp_path, capsys):
    src = write_report(tmp_path / "rep", [entry("x", {"hash": [change()]})])
    assert main([str(src)]) == 1
    assert "OUTPUT_DIR" in capsys.readouterr().err


def test_cli_refuses_existing_output(tmp_path):
    src = write_report(tmp_path / "rep", [entry("x", {"hash": [change()]})])
    out = tmp_path / "out"
    out.mkdir()
    assert main([str(src), "-o", str(out)]) == 1


def test_cli_rejects_unsupported_version_without_writing_output(tmp_path, capsys):
    src = write_report(tmp_path / "rep", [entry("x", {"tag": [change()]})])
    data_js = src / "__deps" / "data.js"
    text = data_js.read_text(encoding="latin-1")
    forged = b"DIFF" + (6).to_bytes(4, "little") + read_blob(text, "diffData")[8:]
    data_js.write_text(replace_blob(text, "diffData", forged), encoding="latin-1")

    out = tmp_path / "out"
    assert main([str(src), "-o", str(out)]) == 1
    assert "unsupported diffData format version 6" in capsys.readouterr().err
    assert not out.exists()  # fail fast: no half-written output directory


def test_cli_explain_lists_suppressed(tmp_path, capsys):
    src = write_report(
        tmp_path / "rep",
        [entry("noise", {"hash": [change()]}, path="/p/drop.dll")],
    )
    main([str(src), "-o", str(tmp_path / "out"), "--explain"])
    err = capsys.readouterr().err
    assert "suppressed  /p/drop.dll  [hash]" in err


# --- real fixture (gitignored, local only) ----------------------------------


@pytest.mark.skipif(
    not HTML_DATA_JS.exists(),
    reason="rl-html report is a local-only fixture (gitignored); not in clean checkouts",
)
def test_real_html_report_reduces_to_signal():
    text = HTML_DATA_JS.read_text(encoding="latin-1")
    _, kept, suppressed = clean_data_js(text)
    assert (kept, suppressed) == (3, 626)


@pytest.mark.skipif(
    not HTML_DATA_JS.exists(),
    reason="rl-html report is a local-only fixture (gitignored); not in clean checkouts",
)
def test_real_html_report_preserves_other_blobs(tmp_path):
    dst = tmp_path / "out"
    shutil.copytree(HTML_DATA_JS.parent.parent, dst)
    clean_html_report(dst)
    src_text = HTML_DATA_JS.read_text(encoding="latin-1")
    out_text = (dst / "__deps" / "data.js").read_text(encoding="latin-1")
    assert read_blob(out_text, "reportData") == read_blob(src_text, "reportData")
    assert read_blob(out_text, "checksData") == read_blob(src_text, "checksData")
