from .helpers import run_module


def test_biometric_benchmark_runs_on_synthetic_data(live_server):
    r = run_module(live_server, "biometric.benchmark.far_frr")
    # EVALUATION_ONLY module still executes; synthetic placeholder is tuned
    # to a sane FAR, so it should pass while being explicitly flagged as
    # synthetic via an info-severity finding.
    assert r.status == "passed", r.summary
    assert "SYNTHETIC" in r.summary
    assert "info" in r.finding_severities


def test_liveness_pad_evaluation_runs_on_synthetic_data(live_server):
    r = run_module(live_server, "liveness.pad.apcer_bpcer_evaluation")
    assert r.status == "passed", r.summary
    assert "SYNTHETIC" in r.summary
    assert "info" in r.finding_severities


def test_android_storage_module_skips_without_device(live_server, monkeypatch):
    # Storage + network config are now wired to the adb harness (see
    # test_layer4_storage_network.py); with no adb they must SKIP, never pass.
    from app.layers.layer4_android import harness

    monkeypatch.delenv("IDENTITYSHIELD_ADB", raising=False)
    monkeypatch.setattr(harness.shutil, "which", lambda _: None)
    r = run_module(live_server, "android.storage.local_data_at_rest")
    assert r.status == "skipped"
    assert r.summary.startswith("skipped: no device")
