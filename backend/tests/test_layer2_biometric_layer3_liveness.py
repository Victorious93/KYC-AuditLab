from .helpers import run_module


def test_biometric_benchmark_runs_on_synthetic_data(live_server):
    r = run_module(live_server, "biometric.benchmark.far_frr")
    # EVALUATION_ONLY module still executes; synthetic placeholder is tuned
    # to a sane FAR, so it should pass while being explicitly flagged as
    # synthetic via an info-severity finding.
    assert r.status == "pass", r.summary
    assert "SYNTHETIC" in r.summary
    assert "info" in r.finding_severities


def test_liveness_pad_evaluation_runs_on_synthetic_data(live_server):
    r = run_module(live_server, "liveness.pad.apcer_bpcer_evaluation")
    assert r.status == "pass", r.summary
    assert "SYNTHETIC" in r.summary
    assert "info" in r.finding_severities


def test_android_modules_are_honest_stubs(live_server):
    r = run_module(live_server, "android.integrity.apk_signature_check")
    assert r.status == "unavailable"
    assert "no attached Android device" in r.summary
