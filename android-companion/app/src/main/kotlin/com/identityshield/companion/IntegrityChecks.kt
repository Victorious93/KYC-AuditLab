package com.identityshield.companion

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

/**
 * Local, on-device checks the IdentityShield Android companion runs against
 * a target app's installed package. These are evaluation/inspection
 * utilities only - they read manifest/package metadata and known
 * environment indicators; none of them modify the target app, defeat its
 * protections, or exfiltrate data off-device.
 *
 * STATUS: written but not built or executed in this session - no Android
 * SDK/device/emulator is available in this environment. Treat this as
 * source to compile and run from Android Studio or a CI job with an
 * attached device, not as verified-working code.
 */
class IntegrityChecks(private val context: Context) {

    data class SignatureInfo(val packageName: String, val signingCertSha256: String?)

    /** Reads the installed package's signing certificate digest so it can be
     * compared against an expected known-good value supplied by the backend
     * orchestrator (which holds the authorized target's expected hash). */
    fun getSigningCertificateDigest(targetPackage: String): SignatureInfo {
        val pm = context.packageManager
        val flags = PackageManager.GET_SIGNING_CERTIFICATES
        val info = pm.getPackageInfo(targetPackage, flags)
        val signer = info.signingInfo?.apkContentsSigners?.firstOrNull()
        val sha256 = signer?.toByteArray()?.let { bytes ->
            java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it) }
        }
        return SignatureInfo(targetPackage, sha256)
    }

    data class PermissionAudit(val permission: String, val isDangerous: Boolean, val granted: Boolean)

    /** Enumerates the target app's requested permissions and flags which are
     * in the Android "dangerous" protection level, for manual/automated
     * review of over-broad permission requests. */
    fun auditPermissions(targetPackage: String): List<PermissionAudit> {
        val pm = context.packageManager
        val info = pm.getPackageInfo(targetPackage, PackageManager.GET_PERMISSIONS)
        val requested = info.requestedPermissions ?: return emptyList()
        return requested.mapIndexed { idx, perm ->
            val flags = info.requestedPermissionsFlags?.getOrNull(idx) ?: 0
            val granted = (flags and android.content.pm.PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
            val isDangerous = try {
                val permInfo = pm.getPermissionInfo(perm, 0)
                (permInfo.protection and android.content.pm.PermissionInfo.PROTECTION_MASK_BASE) ==
                    android.content.pm.PermissionInfo.PROTECTION_DANGEROUS
            } catch (e: PackageManager.NameNotFoundException) {
                false
            }
            PermissionAudit(perm, isDangerous, granted)
        }
    }

    /** Non-exhaustive, best-effort indicators that the CURRENT device (the
     * one running this companion, used as an authorized test fixture) looks
     * rooted/emulated. This is for evaluating whether a target app's OWN
     * root/emulator detection correctly reacts to this known device state -
     * it is not a technique for hiding root status from a target app. */
    fun deviceTrustSignals(): Map<String, Boolean> = mapOf(
        "build_tags_test_keys" to (Build.TAGS?.contains("test-keys") == true),
        "known_emulator_fingerprint" to (Build.FINGERPRINT.startsWith("generic") ||
            Build.MODEL.contains("sdk_gphone") || Build.MANUFACTURER == "Genymotion"),
        "su_binary_present" to listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su"
        ).any { java.io.File(it).exists() },
    )
}
