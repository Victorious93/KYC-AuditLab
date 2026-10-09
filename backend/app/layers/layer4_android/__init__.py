"""Layer 4 - Android Device and Application Security.

IMPORTANT / HONEST STATUS: this orchestrator-side module registers the
intended test interface for Android checks (APK integrity, permission
analysis, local storage, transport security, device-trust signals), but
NONE of it has been executed against a real or emulated device in this
project, because no Android device, emulator, or ADB-reachable target is
attached in this development environment.

The Kotlin companion app under android-companion/ contains real,
compilable instrumentation code for several of these checks (permission
dump via PackageManager, network security config inspection, basic root
indicators). It has NOT been built or run - see docs/LIMITATIONS.md. Do
not report any Android finding as "tested" unless it was actually executed
against a connected device via ADB and the output is attached as evidence.
"""
from __future__ import annotations

from ...orchestrator.registry import Capability, Layer, TestModule, registry


def _unimplemented_adb_check(ctx):  # pragma: no cover - intentionally unreachable
    raise NotImplementedError(
        "ADB-based execution is not wired up in this environment (no device/emulator attached)."
    )


_ANDROID_MODULES = [
    (
        "android.integrity.apk_signature_check",
        "APK signature / integrity check",
        "Verify the installed APK's signing certificate matches the expected release signature.",
    ),
    (
        "android.permissions.dangerous_permission_audit",
        "Dangerous permission audit",
        "Enumerate requested permissions via `adb shell dumpsys package` and flag unused dangerous permissions.",
    ),
    (
        "android.storage.local_data_at_rest",
        "Local storage at-rest check",
        "Pull app-private storage (via a debuggable build or backup) and check for unencrypted PII/credentials.",
    ),
    (
        "android.network.transport_security_config",
        "Network security config check",
        "Parse the app's network_security_config.xml / manifest for cleartext traffic or certificate-pinning gaps.",
    ),
    (
        "android.trust.root_emulator_detection_signal",
        "Root/emulator detection signal check",
        "Confirm the app's own client-side root/emulator detection fires correctly on a rooted test device - evaluation of the app's OWN signal, not a bypass tool for it.",
    ),
]

for module_id, title, description in _ANDROID_MODULES:
    registry.register(
        TestModule(
            id=module_id,
            layer=Layer.ANDROID,
            title=title,
            description=description,
            capability=Capability.STUB_NOT_IMPLEMENTED,
            run=None,
            limitation=(
                "Not executed: this development environment has no attached Android device, "
                "emulator, or ADB connection. The interface and Kotlin-side instrumentation "
                "source exist (see android-companion/) but have not been run. Wiring this up "
                "requires the orchestrator host to have `adb` on PATH and a device/emulator "
                "authorized for debugging; implement via subprocess calls to `adb shell ...` "
                "following the pattern in orchestrator/runner.py, gated by the same "
                "scope.assert_in_scope() check used for network modules."
            ),
        )
    )
