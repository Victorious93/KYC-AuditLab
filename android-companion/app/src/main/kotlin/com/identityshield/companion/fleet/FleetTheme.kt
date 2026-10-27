package com.identityshield.companion.fleet

/**
 * Pure-Kotlin model + defensive parser for the VictorLaunch fleet theme
 * (schemaVersion 1, victorlaunch docs/specs/FLEET_THEME.md). No Android
 * dependencies so it is unit-tested on the JVM.
 */
data class FleetPalette(
    val background: Int,
    val surface: Int,
    val primary: Int,
    val secondary: Int,
    val onBackground: Int,
    val muted: Int,
    val danger: Int,
    val stale: Int,
    val tile: Int,
) {
    companion object {
        /** Built-in theme (the spec's NEON_FLEET example values). Used whenever the
         *  provider is unavailable, unauthorized, or returns something we reject. */
        val BUILT_IN = FleetPalette(
            background = 0xFF0B0C12.toInt(),
            surface = 0xFF161821.toInt(),
            primary = 0xFF00E5FF.toInt(),
            secondary = 0xFFE840FF.toInt(),
            onBackground = 0xFFF5F7FF.toInt(),
            muted = 0xFF9AA3B5.toInt(),
            danger = 0xFFFF6B8A.toInt(),
            stale = 0xFFFFC14D.toInt(),
            tile = 0xCC1A1D2B.toInt(),
        )
    }
}

data class FleetTheme(val mode: String, val palette: FleetPalette, val fromProvider: Boolean) {
    companion object {
        val BUILT_IN = FleetTheme("BUILT_IN", FleetPalette.BUILT_IN, fromProvider = false)
    }
}

object FleetThemeParser {
    const val SUPPORTED_SCHEMA = 1
    private val HEX = Regex("^#([0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})$")
    private val MODES = setOf("LIGHT", "DARK", "NEON_FLEET", "MATERIAL_YOU")

    /** `#RRGGBB` (opaque) or `#AARRGGBB` -> ARGB int; anything else -> null. */
    fun parseColor(raw: String?): Int? {
        val s = raw?.trim() ?: return null
        if (!HEX.matches(s)) return null
        val v = s.substring(1).toLong(16)
        return (if (s.length == 7) v or 0xFF000000L else v).toInt()
    }

    /**
     * Parse one provider row given as column name -> string value. Unknown
     * columns are ignored. Returns null (caller falls back to the built-in
     * theme) when the row is missing or schemaVersion is not exactly 1.
     * Individual bad/missing colors fall back to the built-in value for that slot.
     */
    fun parseRow(row: Map<String, String?>?): FleetTheme? {
        if (row == null) return null
        val version = row["schemaVersion"]?.trim()?.toIntOrNull() ?: return null
        if (version != SUPPORTED_SCHEMA) return null
        val d = FleetPalette.BUILT_IN
        fun c(name: String, def: Int) = parseColor(row[name]) ?: def
        val palette = FleetPalette(
            background = c("background", d.background),
            surface = c("surface", d.surface),
            primary = c("primary", d.primary),
            secondary = c("secondary", d.secondary),
            onBackground = c("onBackground", d.onBackground),
            muted = c("muted", d.muted),
            danger = c("danger", d.danger),
            stale = c("stale", d.stale),
            tile = c("tile", d.tile),
        )
        val mode = row["mode"]?.trim()?.takeIf { it in MODES } ?: "UNKNOWN"
        return FleetTheme(mode, palette, fromProvider = true)
    }
}
