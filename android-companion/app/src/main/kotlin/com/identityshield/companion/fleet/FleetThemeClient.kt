package com.identityshield.companion.fleet

import android.content.Context
import android.content.pm.PackageManager
import android.database.ContentObserver
import android.net.Uri
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.util.Log
import java.security.MessageDigest

/**
 * Read-only client for VictorLaunch's fleet theme provider.
 *
 * - Queries content://com.victorious.launch.theme/current on start and on every
 *   change signal (ContentObserver or the FLEET_THEME_CHANGED broadcast).
 * - Before querying, verifies the provider is owned by com.victorious.launch and
 *   that package's signing cert matches a pin ([FleetPins]).
 * - Never writes the provider. Never uses broadcast extras as data or auth.
 * - Any failure (not installed, pin mismatch, SecurityException, bad row,
 *   schemaVersion != 1) falls back to [FleetTheme.BUILT_IN].
 */
object FleetThemeClient {
    private const val TAG = "FleetThemeClient"
    val CURRENT_URI: Uri = Uri.parse("content://${FleetPins.AUTHORITY}/current")

    private val main = Handler(Looper.getMainLooper())
    private val worker: Handler by lazy { Handler(HandlerThread("fleet-theme").apply { start() }.looper) }
    private val listeners = LinkedHashSet<(FleetTheme) -> Unit>()
    private var observer: ContentObserver? = null
    private var appContext: Context? = null

    @Volatile var current: FleetTheme = FleetTheme.BUILT_IN
        private set

    /** Call from the UI (e.g. Activity.onStart). Idempotent. */
    fun start(context: Context) {
        val app = context.applicationContext
        appContext = app
        if (observer == null) {
            val obs = object : ContentObserver(main) {
                override fun onChange(selfChange: Boolean) = requery(app)
            }
            try {
                app.contentResolver.registerContentObserver(CURRENT_URI, false, obs)
                observer = obs
            } catch (e: SecurityException) {
                Log.w(TAG, "cannot observe theme provider: ${e.message}")
            }
        }
        requery(app)
    }

    fun addListener(l: (FleetTheme) -> Unit) { listeners += l; l(current) }
    fun removeListener(l: (FleetTheme) -> Unit) { listeners -= l }

    /** Re-read the provider off the main thread. Coalesces bursts of signals. */
    fun requery(context: Context) {
        val app = context.applicationContext
        worker.removeCallbacksAndMessages(null)
        worker.postDelayed({
            val theme = load(app)
            main.post {
                current = theme
                listeners.toList().forEach { it(theme) }
            }
        }, 150)
    }

    private fun load(context: Context): FleetTheme = try {
        if (!providerIsTrusted(context)) {
            FleetTheme.BUILT_IN
        } else {
            context.contentResolver.query(CURRENT_URI, null, null, null, null)?.use { c ->
                if (!c.moveToFirst()) null else {
                    val row = HashMap<String, String?>()
                    for (i in 0 until c.columnCount) {
                        row[c.getColumnName(i)] = try { c.getString(i) } catch (_: Exception) { null }
                    }
                    FleetThemeParser.parseRow(row)
                }
            } ?: FleetTheme.BUILT_IN
        }
    } catch (e: SecurityException) {
        Log.i(TAG, "not pinned by VictorLaunch (SecurityException); using built-in theme")
        FleetTheme.BUILT_IN
    } catch (e: Exception) {
        Log.w(TAG, "theme query failed: ${e.javaClass.simpleName}; using built-in theme")
        FleetTheme.BUILT_IN
    }

    private fun providerIsTrusted(context: Context): Boolean {
        val pm = context.packageManager
        val info = pm.resolveContentProvider(FleetPins.AUTHORITY, 0) ?: return false
        if (info.packageName != FleetPins.PROVIDER_PACKAGE) return false
        val pkg = try {
            pm.getPackageInfo(FleetPins.PROVIDER_PACKAGE, PackageManager.GET_SIGNING_CERTIFICATES)
        } catch (_: PackageManager.NameNotFoundException) { return false }
        val signers = pkg.signingInfo?.apkContentsSigners ?: return false
        val digests = signers.map { sig ->
            MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }
        }
        val ok = FleetPins.isTrustedProvider(info.packageName, digests)
        if (!ok) Log.w(TAG, "theme provider cert not pinned; using built-in theme")
        return ok
    }
}
