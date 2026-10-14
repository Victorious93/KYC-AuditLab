package com.identityshield.companion

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import org.json.JSONArray
import org.json.JSONObject

/**
 * Entry point for the backend adb harness:
 *
 *   adb shell am instrument -w -e target_package <pkg> \
 *       com.identityshield.companion/.IntegrityInstrumentation
 *
 * Runs [IntegrityChecks] against <pkg> and returns a single-line JSON payload
 * in the result bundle under "identityshield_json". Read-only: nothing on the
 * target app is modified.
 */
class IntegrityInstrumentation : Instrumentation() {
    private var targetPackage: String? = null

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        targetPackage = arguments?.getString("target_package")
        start()
    }

    override fun onStart() {
        super.onStart()
        val out = JSONObject()
        val code = try {
            val pkg = targetPackage ?: throw IllegalArgumentException("missing -e target_package")
            val checks = IntegrityChecks(context)
            val sig = checks.getSigningCertificateDigest(pkg)
            out.put("targetPackage", pkg)
            out.put("signature", JSONObject().apply {
                put("packageName", sig.packageName)
                put("signingCertSha256", sig.signingCertSha256 ?: JSONObject.NULL)
            })
            out.put("permissions", JSONArray().apply {
                checks.auditPermissions(pkg).forEach { p ->
                    put(JSONObject().apply {
                        put("permission", p.permission)
                        put("isDangerous", p.isDangerous)
                        put("granted", p.granted)
                    })
                }
            })
            out.put("deviceTrustSignals", JSONObject(checks.deviceTrustSignals() as Map<*, *>))
            Activity.RESULT_OK
        } catch (e: Exception) {
            out.put("error", "${e.javaClass.simpleName}: ${e.message}")
            Activity.RESULT_CANCELED
        }
        finish(code, Bundle().apply { putString("identityshield_json", out.toString()) })
    }
}
