package com.identityshield.companion.fleet

/**
 * Who may serve the fleet theme to us. We authorize the PROVIDER by package
 * name + signing-certificate SHA-256 pin; a signature permission alone is not
 * used (fleet apps do not share a signing key).
 *
 * Pin source: victorlaunch keystore/README.md ("Certificate SHA-256" of the
 * dedicated VictorLaunch debug key). Release cert is not published yet, so it
 * is deliberately absent: an empty/TBD slot never authorizes.
 */
object FleetPins {
    const val PROVIDER_PACKAGE = "com.victorious.launch"
    const val AUTHORITY = "com.victorious.launch.theme"
    const val ACTION_THEME_CHANGED = "com.victorious.launch.action.FLEET_THEME_CHANGED"

    val PINNED_PROVIDER_CERTS: Set<String> = setOf(
        // VictorLaunch debug (keystore/README.md)
        normalize("B9:9A:AF:E2:C1:41:8B:5D:64:AA:0D:4B:AC:61:FC:F7:A7:BA:81:44:35:E0:EF:89:E8:AA:55:BE:56:4E:4A:69"),
    )

    /** Explicitly revoked by VictorLaunch (old committed debug key, password "android"). */
    val REVOKED_CERTS: Set<String> = setOf(
        normalize("1B:06:A8:9E:7F:F5:BA:21:C9:A4:F8:F1:F0:4F:95:E5:62:78:A1:22:18:AD:37:33:28:CE:E7:83:1D:4F:BA:CA"),
    )

    /** Colon-, whitespace- and case-insensitive; returns "" for null/blank. */
    fun normalize(sha256: String?): String =
        sha256.orEmpty().replace(":", "").replace(" ", "").lowercase()

    /**
     * True only if [packageName] is VictorLaunch AND it has at least one signer
     * AND every current signer is pinned (none revoked, none blank).
     */
    fun isTrustedProvider(
        packageName: String?,
        signerSha256s: List<String>,
        pinned: Set<String> = PINNED_PROVIDER_CERTS,
        revoked: Set<String> = REVOKED_CERTS,
    ): Boolean {
        if (packageName != PROVIDER_PACKAGE) return false
        if (signerSha256s.isEmpty()) return false
        return signerSha256s.all { raw ->
            val n = normalize(raw)
            n.length == 64 && n !in revoked && n in pinned
        }
    }
}
