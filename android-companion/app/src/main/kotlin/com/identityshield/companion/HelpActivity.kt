package com.identityshield.companion

import android.app.Activity
import android.os.Bundle
import android.util.TypedValue
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/**
 * Static, offline Help screen: a short how-to plus a pointer to docs/MANUAL.md.
 * It performs no checks, needs no permissions and makes no network calls.
 * The real work is still done by [IntegrityInstrumentation] over adb.
 */
class HelpActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 16f, resources.displayMetrics).toInt()
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            addView(TextView(this@HelpActivity).apply {
                setText(R.string.help_title)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
                setPadding(0, 0, 0, pad)
            })
            addView(TextView(this@HelpActivity).apply {
                setText(R.string.help_body)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
                setTextIsSelectable(true)
            })
        }
        setContentView(ScrollView(this).apply { addView(column) })
    }
}
