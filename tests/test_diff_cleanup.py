import json
from pathlib import Path

import pytest

from diff_cleanup import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_DENY_KEYS,
    STRUCTURAL_CHANGE_KEYS,
    clean_report,
    is_signal,
    load_deny_keys,
)

DATA = Path(__file__).parent / "data"
FIXTURE = DATA / "report.rl-diff-diff-with-4.4.32.159.json"
GLASSWORM = DATA / "report.rl-diff-glassworm-malicious.json"


def entry(changes=None, violations=None, warnings=None):
    return {
        "changes": changes or {},
        "violations": violations or [],
        "warnings": warnings or [],
    }


def test_structural_only_is_noise():
    assert not is_signal(entry({"hash": [], "name": [], "size": []}))


def test_no_changes_is_noise():
    assert not is_signal(entry())


def test_functionality_change_is_signal():
    assert is_signal(entry({"hash": [], "functionality": []}))


def test_action_change_is_signal():
    assert is_signal(entry({"name": [], "action": []}))


def test_entropy_with_structural_only_is_noise():
    # entropy is byte-derived: it shifts on any content change, so {hash,size,entropy}
    # is pure churn. A 2026-06-10 Marketing crawl found 1499 such entries.
    assert not is_signal(entry({"hash": [], "size": [], "entropy": []}))


def test_entropy_with_signal_still_signal():
    # entropy never masks a real signal key — tag here keeps the entry.
    assert is_signal(entry({"hash": [], "size": [], "entropy": [], "tag": []}))


def test_unknown_change_key_is_signal():
    # Conservative: a category we have never seen is kept, not suppressed.
    assert is_signal(entry({"hash": [], "some_future_key": []}))


def test_violations_force_signal():
    assert is_signal(entry({"hash": []}, violations=[{"id": "SQ1"}]))


def test_warnings_force_signal():
    assert is_signal(entry({"name": []}, warnings=["heads up"]))


def test_clean_report_filters_diff():
    report = {"report": {"diff": [entry({"functionality": []}), entry({"hash": []})]}}
    cleaned, kept, suppressed = clean_report(report)
    assert (kept, suppressed) == (1, 1)
    assert cleaned["report"]["diff"] == [entry({"functionality": []})]


def test_clean_report_does_not_mutate_input():
    report = {"report": {"diff": [entry({"hash": []})]}}
    clean_report(report)
    assert len(report["report"]["diff"]) == 1


def test_clean_report_rejects_non_rl_diff():
    with pytest.raises(ValueError):
        clean_report({"report": {}})


@pytest.mark.skipif(
    not FIXTURE.exists(),
    reason="HP SureClick scan is a local-only fixture (gitignored); not present in clean checkouts",
)
def test_real_fixture_reduces_to_signal():
    report = json.loads(FIXTURE.read_text())
    cleaned, kept, suppressed = clean_report(report)
    assert (kept, suppressed) == (21, 608)
    assert all(is_signal(e) for e in cleaned["report"]["diff"])


def test_classification_alone_is_signal():
    # A file newly classified malicious must surface even if nothing else changed
    # beyond its content hash. classification is not in the structural set.
    assert is_signal(entry({"hash": [], "classification": []}))


def test_malicious_reclassification_is_never_suppressed():
    # Real Portal fixture: GlassWorm/DarkTheme@3.11.4, a VS Code / npm supply-chain
    # worm. Six files transition to classification "malicious". The cleaner must
    # keep every one of them.
    report = json.loads(GLASSWORM.read_text())
    cleaned, _, _ = clean_report(report)
    kept = cleaned["report"]["diff"]

    def became_malicious(e):
        return any(
            c.get("current") == "malicious" for c in e.get("changes", {}).get("classification", [])
        )

    source = json.loads(GLASSWORM.read_text())["report"]["diff"]
    malicious = [e for e in source if became_malicious(e)]
    assert len(malicious) == 6
    kept_paths = {e["file"]["path"] for e in kept}
    assert all(e["file"]["path"] in kept_paths for e in malicious)


# --- configurable allow/deny ------------------------------------------------


def write_config(tmp_path, body):
    path = tmp_path / "config.toml"
    path.write_text(body)
    return path


def test_default_deny_keys_loaded_from_bundled_toml():
    # DEFAULT_DENY_KEYS is read from the shipped config at import — it is the
    # single source of truth. Pin the expected structural set so an accidental
    # edit to default_config.toml that changes behavior is caught.
    assert DEFAULT_DENY_KEYS == frozenset({"hash", "name", "size", "entropy"})
    assert load_deny_keys(DEFAULT_CONFIG_PATH) == DEFAULT_DENY_KEYS


def test_structural_change_keys_alias():
    assert STRUCTURAL_CHANGE_KEYS == DEFAULT_DENY_KEYS


def test_load_deny_keys_returns_only_denied(tmp_path):
    cfg = write_config(
        tmp_path,
        '[changes]\nhash = "deny"\nname = "deny"\ntag = "allow"\n',
    )
    assert load_deny_keys(cfg) == frozenset({"hash", "name"})


def test_load_deny_keys_rejects_bad_value(tmp_path):
    cfg = write_config(tmp_path, '[changes]\nhash = "suppress"\n')
    with pytest.raises(ValueError):
        load_deny_keys(cfg)


def test_load_deny_keys_empty_config(tmp_path):
    cfg = write_config(tmp_path, "")
    assert load_deny_keys(cfg) == frozenset()


def test_config_can_promote_a_key_to_signal():
    # User decides 'name' changes matter: with name no longer denied, a
    # name-only structural entry is kept.
    deny = frozenset({"hash", "size", "entropy"})
    assert is_signal(entry({"hash": [], "name": []}), deny)


def test_config_can_demote_a_signal_key_to_noise():
    # User decides 'tag' churn is noise here: deny it and a tag-only entry drops.
    deny = frozenset({"hash", "name", "size", "entropy", "tag"})
    assert not is_signal(entry({"hash": [], "tag": []}), deny)


def test_unlisted_key_kept_under_custom_config():
    # Conservative default survives a custom config: a category the config does
    # not mention is still kept.
    deny = frozenset({"hash"})
    assert is_signal(entry({"hash": [], "never_seen": []}), deny)


def test_clean_report_honors_custom_deny_keys():
    report = {"report": {"diff": [entry({"tag": []}), entry({"hash": []})]}}
    deny = frozenset({"hash", "tag"})
    _, kept, suppressed = clean_report(report, deny)
    assert (kept, suppressed) == (0, 2)
