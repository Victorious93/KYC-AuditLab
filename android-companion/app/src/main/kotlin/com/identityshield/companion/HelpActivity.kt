package com.identityshield.companion

import android.os.Bundle
import android.util.TypedValue
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.identityshield.companion.fleet.FleetPalette
import com.identityshield.companion.fleet.ThemedActivity

/**
 * Static, offline Help screen: a short how-to plus a pointer to docs/MANUAL.md.
 * Colours follow the VictorLaunch fleet theme when it is available and pinned,
 * otherwise the built-in theme. No network calls; the real work is still done
 * by [IntegrityInstrumentation] over adb.
 */
class HelpActivity : ThemedActivity() {
    private lateinit var root: ScrollView
    private lateinit var title: TextView
    private lateinit var body: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 16f, resources.displayMetrics).toInt()
        title = TextView(this).apply {
            setText(R.string.help_title)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
            setPadding(0, 0, 0, pad)
        }
        body = TextView(this).apply {
            setText(R.string.help_body)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
            setTextIsSelectable(true)
        }
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            addView(title)
            addView(body)
        }
        root = ScrollView(this).apply { addView(column) }
        setContentView(root)
        applyTheme(FleetPalette.BUILT_IN)
    }

    override fun applyTheme(p: FleetPalette) {
        root.bg(p.background)
        title.setTextColor(p.primary)
        body.setTextColor(p.onBackground)
        body.setLinkTextColor(p.secondary)
        window?.statusBarColor = p.surface
    }
}
