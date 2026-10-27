package com.identityshield.companion.fleet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FleetThemeParserTest {
    private fun row(vararg kv: Pair<String, String?>) = mapOf(*kv)

    @Test fun parsesBothHexForms() {
        assertEquals(0xFF00E5FF.toInt(), FleetThemeParser.parseColor("#00E5FF"))
        assertEquals(0xCC1A1D2B.toInt(), FleetThemeParser.parseColor("#CC1A1D2B"))
        assertEquals(0xFFAABBCC.toInt(), FleetThemeParser.parseColor(" #aabbcc "))
    }

    @Test fun rejectsBadColors() {
        listOf(null, "", "red", "#FFF", "#GG0000", "00E5FF", "#1234567", "#123456789", "rgb(0,0,0)")
            .forEach { assertNull(it, FleetThemeParser.parseColor(it)) }
    }

    @Test fun validRowApplied_badColorsFallBackPerSlot() {
        val t = FleetThemeParser.parseRow(row(
            "schemaVersion" to "1", "mode" to "LIGHT",
            "primary" to "#FF112233", "secondary" to "nope", "unknownColumn" to "x",
        ))!!
        assertTrue(t.fromProvider)
        assertEquals("LIGHT", t.mode)
        assertEquals(0xFF112233.toInt(), t.palette.primary)
        assertEquals(FleetPalette.BUILT_IN.secondary, t.palette.secondary)
        assertEquals(FleetPalette.BUILT_IN.background, t.palette.background)
    }

    @Test fun rejectsOtherSchemaVersions() {
        listOf("0", "2", "-1", "1.0", "", "abc", null).forEach {
            assertNull("v=$it", FleetThemeParser.parseRow(row("schemaVersion" to it, "primary" to "#FF112233")))
        }
        assertNull(FleetThemeParser.parseRow(row("primary" to "#FF112233")))
        assertNull(FleetThemeParser.parseRow(null))
    }

    @Test fun unknownModeIsNotTrusted() {
        assertEquals("UNKNOWN", FleetThemeParser.parseRow(row("schemaVersion" to "1", "mode" to "<script>"))!!.mode)
    }
}

class FleetPinsTest {
    private val pin = "B9:9A:AF:E2:C1:41:8B:5D:64:AA:0D:4B:AC:61:FC:F7:A7:BA:81:44:35:E0:EF:89:E8:AA:55:BE:56:4E:4A:69"
    private val revoked = "1B:06:A8:9E:7F:F5:BA:21:C9:A4:F8:F1:F0:4F:95:E5:62:78:A1:22:18:AD:37:33:28:CE:E7:83:1D:4F:BA:CA"
    private val other = "22:4F:C1:64:D6:8A:28:88:B9:FE:8F:10:C7:B6:B5:E5:78:67:2B:D2:F8:97:05:06:68:4B:23:A9:43:FA:44:1D"

    @Test fun pinnedVictorLaunchTrusted_caseAndColonInsensitive() {
        assertTrue(FleetPins.isTrustedProvider("com.victorious.launch", listOf(pin)))
        assertTrue(FleetPins.isTrustedProvider("com.victorious.launch", listOf(pin.replace(":", "").lowercase())))
    }

    @Test fun wrongPackageRejectedEvenWithPinnedCert() {
        assertFalse(FleetPins.isTrustedProvider("com.evil.launch", listOf(pin)))
        assertFalse(FleetPins.isTrustedProvider(null, listOf(pin)))
    }

    @Test fun mismatchRevokedEmptyAndMixedRejected() {
        assertFalse(FleetPins.isTrustedProvider("com.victorious.launch", listOf(other)))
        assertFalse(FleetPins.isTrustedProvider("com.victorious.launch", listOf(revoked)))
        assertFalse(FleetPins.isTrustedProvider("com.victorious.launch", emptyList()))
        assertFalse(FleetPins.isTrustedProvider("com.victorious.launch", listOf("")))
        assertFalse(FleetPins.isTrustedProvider("com.victorious.launch", listOf(pin, other)))
    }

    @Test fun revokedWinsEvenIfAlsoPinned() {
        val n = FleetPins.normalize(revoked)
        assertFalse(FleetPins.isTrustedProvider("com.victorious.launch", listOf(revoked), pinned = setOf(n)))
    }
}
