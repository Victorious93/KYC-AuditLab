package com.identityshield.companion

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.res.Resources
import android.os.Build
import android.os.Environment
import org.json.JSONArray
import org.json.JSONObject
import org.xmlpull.v1.XmlPullParser
import java.io.File

/**
 * Read-only, non-root inspection of a target package's local-storage exposure
 * and network security configuration. Uses only public PackageManager APIs and
 * the target's own APK resources (binary AndroidManifest.xml and its
 * network_security_config XML, opened through createPackageContext). Nothing is
 * modified on the target and no target data leaves the device; file checks only
 * probe whether paths are readable/listable by an unrelated app.
 *
 * Manifest-derived values are best-effort: if the binary manifest cannot be
 * parsed, those fields are reported as null with a "manifestParseError".
 */
class AppExposureChecks(private val context: Context) {

    private val androidNs = "http://schemas.android.com/apk/res/android"

    /** Attributes of the target's <application> element, read from its binary manifest. */
    private data class ManifestApp(
        val allowBackup: Boolean?,
        val debuggable: Boolean?,
        val usesCleartextTraffic: Boolean?,
        val requestLegacyExternalStorage: Boolean?,
        val fullBackupContentRes: Int?,
        val fullBackupContentBool: Boolean?,
        val dataExtractionRulesRes: Int?,
        val networkSecurityConfigRes: Int?,
        val externalStoragePermissions: List<String>,
    )

    private fun pkgResources(pkg: String): Resources =
        context.createPackageContext(pkg, Context.CONTEXT_IGNORE_SECURITY).resources

    private fun parseManifest(pkg: String): ManifestApp {
        val pkgCtx = context.createPackageContext(pkg, Context.CONTEXT_IGNORE_SECURITY)
        val parser = pkgCtx.assets.openXmlResourceParser("AndroidManifest.xml")
        var app: ManifestApp? = null
        val extPerms = mutableListOf<String>()
        parser.use { p ->
            var ev = p.eventType
            while (ev != XmlPullParser.END_DOCUMENT) {
                if (ev == XmlPullParser.START_TAG) {
                    when (p.name) {
                        "uses-permission" -> {
                            val n = p.getAttributeValue(androidNs, "name")
                            if (n != null && (n.endsWith("EXTERNAL_STORAGE") || n == "android.permission.MANAGE_EXTERNAL_STORAGE")) extPerms.add(n)
                        }
                        "application" -> {
                            fun bool(name: String): Boolean? =
                                if (p.getAttributeValue(androidNs, name) == null) null
                                else p.getAttributeBooleanValue(androidNs, name, false)
                            fun res(name: String): Int? =
                                p.getAttributeResourceValue(androidNs, name, 0).takeIf { it != 0 }
                            val fbcRes = res("fullBackupContent")
                            app = ManifestApp(
                                allowBackup = bool("allowBackup"),
                                debuggable = bool("debuggable"),
                                usesCleartextTraffic = bool("usesCleartextTraffic"),
                                requestLegacyExternalStorage = bool("requestLegacyExternalStorage"),
                                fullBackupContentRes = fbcRes,
                                fullBackupContentBool = if (fbcRes == null) bool("fullBackupContent") else null,
                                dataExtractionRulesRes = res("dataExtractionRules"),
                                networkSecurityConfigRes = res("networkSecurityConfig"),
                                externalStoragePermissions = emptyList(),
                            )
                        }
                    }
                }
                ev = p.next()
            }
        }
        val a = app ?: throw IllegalStateException("no <application> element in manifest")
        return a.copy(externalStoragePermissions = extPerms)
    }

    private fun nullable(v: Any?): Any = v ?: JSONObject.NULL

    private fun probe(path: String?): JSONObject = JSONObject().apply {
        put("path", nullable(path))
        if (path == null) { put("exists", JSONObject.NULL); return@apply }
        val f = File(path)
        put("readable", f.canRead())
        val listed = try { f.list() } catch (e: SecurityException) { null }
        put("listable", listed != null)
        // Only names of entries that this unrelated app can actually read; contents are never read.
        val readable = JSONArray()
        listed?.take(200)?.forEach { name -> if (File(f, name).let { it.isFile && it.canRead() }) readable.put(name) }
        put("readableEntries", readable)
    }

    fun localStorage(pkg: String): JSONObject {
        val ai: ApplicationInfo = context.packageManager.getApplicationInfo(pkg, 0)
        val out = JSONObject()
        out.put("targetSdkVersion", ai.targetSdkVersion)
        // Flags from ApplicationInfo are authoritative (public API).
        out.put("allowBackup", (ai.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0)
        out.put("debuggable", (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0)
        out.put("usesCleartextTraffic", (ai.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0)
        try {
            val m = parseManifest(pkg)
            out.put("requestLegacyExternalStorage", nullable(m.requestLegacyExternalStorage))
            out.put("fullBackupContentSet", m.fullBackupContentRes != null || m.fullBackupContentBool != null)
            out.put("dataExtractionRulesSet", m.dataExtractionRulesRes != null)
            out.put("externalStoragePermissions", JSONArray(m.externalStoragePermissions))
        } catch (e: Exception) {
            out.put("requestLegacyExternalStorage", JSONObject.NULL)
            out.put("fullBackupContentSet", JSONObject.NULL)
            out.put("dataExtractionRulesSet", JSONObject.NULL)
            out.put("externalStoragePermissions", JSONObject.NULL)
            out.put("manifestParseError", "${e.javaClass.simpleName}: ${e.message}")
        }
        out.put("dataDir", probe(ai.dataDir))
        out.put("filesDir", probe(ai.dataDir?.let { "$it/files" }))
        out.put("sharedPrefsDir", probe(ai.dataDir?.let { "$it/shared_prefs" }))
        @Suppress("DEPRECATION")
        val ext = Environment.getExternalStorageDirectory()?.absolutePath
        out.put("externalAppDir", probe(ext?.let { "$it/Android/data/$pkg" }))
        out.put("probeSdk", Build.VERSION.SDK_INT)
        return out
    }

    fun networkConfig(pkg: String): JSONObject {
        val ai = context.packageManager.getApplicationInfo(pkg, 0)
        val out = JSONObject()
        out.put("targetSdkVersion", ai.targetSdkVersion)
        out.put("usesCleartextTraffic", (ai.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0)
        out.put("debuggable", (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0)
        val m = try { parseManifest(pkg) } catch (e: Exception) {
            out.put("manifestParseError", "${e.javaClass.simpleName}: ${e.message}")
            out.put("networkSecurityConfigPresent", JSONObject.NULL)
            return out
        }
        val resId = m.networkSecurityConfigRes
        out.put("networkSecurityConfigPresent", resId != null)
        if (resId == null) return out
        try {
            out.put("networkSecurityConfig", parseNsc(pkgResources(pkg), resId))
        } catch (e: Exception) {
            out.put("nscParseError", "${e.javaClass.simpleName}: ${e.message}")
        }
        return out
    }

    /** Parses <network-security-config> into base-config / domain-configs / debug-overrides. */
    private fun parseNsc(res: Resources, resId: Int): JSONObject {
        val base = JSONObject()
        val domains = JSONArray()
        var debug: JSONObject? = null
        val stack = ArrayDeque<JSONObject>()
        res.getXml(resId).use { p ->
            var ev = p.eventType
            while (ev != XmlPullParser.END_DOCUMENT) {
                if (ev == XmlPullParser.START_TAG) {
                    val cur = stack.lastOrNull()
                    when (p.name) {
                        "base-config", "domain-config", "debug-overrides" -> {
                            val o = when (p.name) { "base-config" -> base; "debug-overrides" -> JSONObject().also { debug = it }; else -> JSONObject() }
                            p.getAttributeValue(null, "cleartextTrafficPermitted")?.let { o.put("cleartextTrafficPermitted", it == "true") }
                            o.put("trustAnchors", JSONArray()); o.put("domains", JSONArray()); o.put("pins", 0)
                            if (p.name == "domain-config") domains.put(o)
                            stack.addLast(o)
                        }
                        "domain" -> cur?.getJSONArray("domains")?.put(JSONObject().apply {
                            put("includeSubdomains", p.getAttributeValue(null, "includeSubdomains") == "true")
                            put("name", p.nextText().trim())
                        })
                        "certificates" -> cur?.getJSONArray("trustAnchors")?.put(
                            p.getAttributeValue(null, "src") ?: "unknown")
                        "pin-set" -> cur?.put("pinExpiration", nullable(p.getAttributeValue(null, "expiration")))
                        "pin" -> cur?.put("pins", cur.optInt("pins") + 1)
                    }
                } else if (ev == XmlPullParser.END_TAG && p.name in setOf("base-config", "domain-config", "debug-overrides")) {
                    stack.removeLastOrNull()
                }
                ev = p.next()
            }
        }
        return JSONObject().apply {
            put("baseConfig", base)
            put("domainConfigs", domains)
            put("debugOverrides", nullable(debug))
        }
    }
}
