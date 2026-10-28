package com.identityshield.companion.fleet

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Wake-up for com.victorious.launch.action.FLEET_THEME_CHANGED.
 *
 * Exported because VictorLaunch sends it explicitly to our package. Any app
 * could send the same action, so it is treated purely as "maybe re-check":
 * extras are never read, and the only effect is a read-only re-query of the
 * pin-verified provider (debounced). A forged broadcast can at most cause a
 * harmless extra query.
 */
class FleetThemeChangedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != FleetPins.ACTION_THEME_CHANGED) return
        FleetThemeClient.requery(context)
    }
}
