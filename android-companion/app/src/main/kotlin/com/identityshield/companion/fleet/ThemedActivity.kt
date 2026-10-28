package com.identityshield.companion.fleet

import android.app.Activity
import android.view.View

/** Base for companion activities: starts the theme client and re-applies the palette live. */
abstract class ThemedActivity : Activity() {
    private val listener: (FleetTheme) -> Unit = { applyTheme(it.palette) }

    override fun onStart() {
        super.onStart()
        FleetThemeClient.start(this)
        FleetThemeClient.addListener(listener)
    }

    override fun onStop() {
        FleetThemeClient.removeListener(listener)
        super.onStop()
    }

    /** Apply palette.* to this activity's views. */
    protected abstract fun applyTheme(p: FleetPalette)

    protected fun View.bg(color: Int) = setBackgroundColor(color)
}
