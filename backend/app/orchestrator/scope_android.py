"""Scope enforcement for Layer 4 (Android) targets.

Layer 4 targets are Android package names that end up on the device shell
via `adb shell am instrument ... -e target_package <pkg>`. `adb shell` joins
its argv and the device's /system/bin/sh re-parses it, so the host-level
allowlist in `scope.py` is not enough on its own: a target such as
`com.android.settings/ ;<cmd>` has host `com.android.settings` but would run
`<cmd>` on the device. The runner therefore also requires a strict package
name for every Layer 4 module, before the module (and adb) is ever invoked.

The same pattern is re-checked in `layers/layer4_android/harness.py`
(defence in depth); a unit test keeps the two identical.
"""
from __future__ import annotations

import re

from .scope import ScopeViolation

ANDROID_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
ANDROID_PACKAGE_MAX_LEN = 255


def validate_android_package(target: str) -> str:
    """Return `target` unchanged if it is a well-formed Android package name,
    else raise ScopeViolation. No normalization: package names are
    case-sensitive and must reach the device exactly as validated."""
    if (
        not isinstance(target, str)
        or len(target) > ANDROID_PACKAGE_MAX_LEN
        or not ANDROID_PACKAGE_RE.fullmatch(target)
    ):
        raise ScopeViolation(
            f"Target {target!r} is not a valid Android package name "
            "(expected e.g. 'com.example.app'). Refusing to execute."
        )
    return target
