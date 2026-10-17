import csv

from app.layers.fixtures import LAYER2_SCORES_CSV, LAYER3_PAD_CSV
from app.layers.layer2_biometric import _load_scores_csv, compute_far_frr
from app.layers.layer3_liveness import PADCase, evaluate_detector

from .helpers import run_module


def test_fixtures_are_synthetic_and_balanced():
    rows = list(csv.DictReader(open(LAYER2_SCORES_CSV)))
    assert len(rows) == 200 and {r["label"] for r in rows} == {"genuine", "impostor"}
    pad = list(csv.DictReader(open(LAYER3_PAD_CSV)))
    assert len(pad) == 120 and all(r["expected_challenge"].startswith("SPECIMEN-") for r in pad)
    assert not any(r["attack_type"] == "genuine" and r["challenge_response"] != r["expected_challenge"] for r in pad)
    assert not any(r["is_attack"] == "1" and r["challenge_response"] == r["expected_challenge"] for r in pad)


def test_metric_math_known_values():
    s = _load_scores_csv(str(LAYER2_SCORES_CSV))
    assert compute_far_frr(s, 0.0) == (1.0, 0.0)
    assert compute_far_frr(s, 1.01) == (0.0, 1.0)
    cases = [PADCase("a", True, 0.9), PADCase("b", True, 0.1), PADCase("g", False, 0.2), PADCase("h", False, 0.9)]
    m = evaluate_detector(cases, lambda c: c.mock_confidence >= 0.5)
    assert (m["apcer"], m["bpcer"], m["acer"]) == (0.5, 0.5, 0.5)


def test_biometric_simulator_matches_offline_threshold(live_server):
    # The simulator's only face rule is score >= 0.80, so end-to-end FAR/FRR
    # must equal the offline computation at 0.80 on the same fixture.
    far, frr = compute_far_frr(_load_scores_csv(str(LAYER2_SCORES_CSV)), 0.80)
    r = run_module(live_server, "biometric.benchmark.far_frr")
    assert "SYNTHETIC" in r.summary and "end-to-end" in r.summary
    assert f"FAR={far:.4f}, FRR={frr:.4f}" in r.summary, r.summary
    assert "info" in r.finding_severities


def test_liveness_pad_flags_client_assertion_in_vulnerable_mode(live_server):
    r = run_module(live_server, "liveness.pad.apcer_bpcer_evaluation")
    # Vulnerable simulator trusts client_asserts_live -> 20/60 attacks accepted.
    assert r.status == "failed", r.summary
    assert "APCER=0.3333, BPCER=0.0000" in r.summary, r.summary
    assert "'client_asserts_live': '20/20'" in r.summary
    assert "high" in r.finding_severities


def test_liveness_pad_with_custom_cases_still_supported(live_server):
    cases = [PADCase("a", True, 0.1), PADCase("g", False, 0.9)]
    r = run_module(live_server, "liveness.pad.apcer_bpcer_evaluation", {"cases": cases})
    assert r.status == "passed" and "APCER=0.0000" in r.summary


def test_android_storage_module_skips_without_device(live_server, monkeypatch):
    from app.layers.layer4_android import harness

    import requests

    from app.orchestrator import scope

    from .helpers import ADMIN_HEADERS

    # Layer 4 targets must be Android package names (a host:port is now
    # rejected by scope before adb is touched), so scope a package.
    monkeypatch.setattr(scope.settings, "allowed_targets", list(scope.settings.allowed_targets) + ["com.example.kyc"])
    requests.post(f"http://{live_server}/scope", json={"target": "com.example.kyc"}, headers=ADMIN_HEADERS, timeout=5)
    monkeypatch.delenv("IDENTITYSHIELD_ADB", raising=False)
    monkeypatch.setattr(harness.shutil, "which", lambda _: None)
    r = run_module("com.example.kyc", "android.storage.local_data_at_rest")
    assert r.status == "skipped"
    assert r.summary.startswith("skipped: no device")
