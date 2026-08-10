import javax.smartcardio.*;
import java.io.ByteArrayOutputStream;
import java.util.*;

/**
 * Change a card PIN on a cyberJack (class-3) reader.
 *
 * Flow: VERIFY the OLD PIN (this already returns 9000), then run ONE change
 * attempt. Find the change variant the reader accepts by uncommenting exactly
 * one line in the "CHANGE ATTEMPTS" block below, then: compile, run, read SW.
 *
 *   javac PinModifyDirect.java
 *   java  PinModifyDirect
 *
 * No command-line flags. Card-specific values are the constants just below.
 * Java 8 compatible. Run from a console so you see the output.
 */
public class PinModifyDirect {

    // ===================== EDIT THESE IF NEEDED =====================
    private static final byte P2        = (byte) 0x81;  // PIN reference (confirmed for this card)
    private static final int  PIN_MIN   = 6;            // min PIN digits
    private static final int  PIN_MAX   = 8;            // max PIN digits
    private static final byte BM_FORMAT = (byte) 0x02;  // bmFormatString
    private static final byte BM_BLOCK  = (byte) 0x08;  // bmPINBlockString (8-byte block)
    private static final byte BM_LENFMT = (byte) 0x00;  // bmPINLengthFormat
    // ================================================================

    private static int ctlCode(int code) { return 0x310000 | (code << 2); }
    private static final int GET_FEATURE_REQUEST       = 3400;
    private static final int FEATURE_VERIFY_PIN_DIRECT = 0x06;
    private static final int FEATURE_MODIFY_PIN_DIRECT = 0x07;

    private static Card card;
    private static int verifyCtl, modifyCtl;

    public static void main(String[] args) throws Exception {
        CardTerminal terminal = pickTerminal(args);
        if (terminal == null) { System.out.println("No cyberJack reader found."); return; }
        System.out.println("Using reader: " + terminal.getName());

        card = terminal.connect("*");
        try {
            System.out.println("ATR: " + hex(card.getATR().getBytes()));
            card.beginExclusive();
            try {
                Map<Integer,Integer> features = discoverFeatures(card);
                System.out.println("Features: " + tagNames(features.keySet()));
                Integer v = features.get(FEATURE_VERIFY_PIN_DIRECT);
                Integer m = features.get(FEATURE_MODIFY_PIN_DIRECT);
                if (v == null || m == null) { System.out.println("Reader lacks VERIFY/MODIFY direct."); return; }
                verifyCtl = v; modifyCtl = m;
                System.out.printf("P2=%02X  PIN %d..%d  format=%02X block=%02X lenfmt=%02X%n",
                        P2 & 0xFF, PIN_MIN, PIN_MAX, BM_FORMAT & 0xFF, BM_BLOCK & 0xFF, BM_LENFMT & 0xFF);

                // ---- STEP 1: always verify the OLD PIN first ----
                System.out.println("\n>>> Enter the OLD PIN at the keypad <<<");
                if (run(verifyCtl, buildVerify(), "VERIFY old") != 0x9000) {
                    System.out.println("Stop: VERIFY must be 9000 before a change. Retry / check old PIN.");
                    return;
                }

                // ============ CHANGE ATTEMPTS ============
                // Leave EXACTLY ONE line uncommented. Comment it out and enable the
                // next one if you don't get SW=9000. After each edit: recompile + run.
                System.out.println("\n>>> Enter the NEW PIN, then the NEW PIN again <<<");

                run(modifyCtl, newOnly(0x01, 1), "A newonly confirm=01 nummsg=1");
                //run(modifyCtl, newOnly(0x01, 2), "B newonly confirm=01 nummsg=2");
                //run(modifyCtl, newOnly(0x01, 3), "C newonly confirm=01 nummsg=3");
                //run(modifyCtl, newOnly(0x03, 2), "D newonly confirm=03 nummsg=2");
                //run(modifyCtl, newOnly(0x00, 1), "E newonly confirm=00 nummsg=1 (no re-enter)");
                //run(modifyCtl, combined(),       "F combined old+new (card rejected this before)");
                // ========================================

            } finally {
                card.endExclusive();
            }
        } finally {
            card.disconnect(false);
        }
    }

    private static int run(int ctl, byte[] struct, String label) {
        System.out.println("\n[" + label + "] struct=" + hex(struct));
        try {
            int sw = swOf(card.transmitControlCommand(ctl, struct));
            System.out.printf("[%s] SW=%04X -> %s%n", label, sw, describe(sw));
            return sw;
        } catch (CardException e) {
            System.out.println("[" + label + "] READER ERROR: " + e.getMessage()
                    + "  -> reader rejected this structure; enable the next variant.");
            return -1;
        }
    }

    /** VERIFY apdu: 00 20 00 P2 08 + 8-byte block. */
    private static byte[] buildVerify() {
        byte[] apdu = new byte[]{0x00, 0x20, 0x00, P2, 0x08, 0,0,0,0,0,0,0,0};
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0x00); b.write(0x00);
        b.write(BM_FORMAT); b.write(BM_BLOCK); b.write(BM_LENFMT);
        b.write(PIN_MIN); b.write(PIN_MAX);
        b.write(0x02);                 // bEntryValidationCondition
        b.write(0x01);                 // bNumberMessage
        b.write(0x09); b.write(0x04);  // wLangId
        b.write(0x00);                 // bMsgIndex
        b.write(0x00); b.write(0x00); b.write(0x00);
        b.write(apdu.length & 0xFF); b.write(0); b.write(0); b.write(0);
        b.write(apdu, 0, apdu.length);
        return b.toByteArray();
    }

    /** New-only CHANGE: 00 24 01 P2 08 + new block. confirmPin/numMsg vary per attempt. */
    private static byte[] newOnly(int confirmPin, int numMsg) {
        byte[] apdu = new byte[]{0x00, 0x24, 0x01, P2, 0x08, 0,0,0,0,0,0,0,0};
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0x00); b.write(0x00);
        b.write(BM_FORMAT); b.write(BM_BLOCK); b.write(BM_LENFMT);
        b.write(0x00);                 // bInsertionOffsetOld (none)
        b.write(0x05);                 // bInsertionOffsetNew
        b.write(PIN_MIN); b.write(PIN_MAX);
        b.write(confirmPin);           // bConfirmPIN
        b.write(0x02);                 // bEntryValidationCondition
        b.write(numMsg);               // bNumberMessage
        b.write(0x09); b.write(0x04);  // wLangId
        for (int i = 0; i < numMsg; i++) b.write(i);     // bMsgIndex1..N
        b.write(0x00); b.write(0x00); b.write(0x00);
        b.write(apdu.length & 0xFF); b.write(0); b.write(0); b.write(0);
        b.write(apdu, 0, apdu.length);
        return b.toByteArray();
    }

    /** Combined CHANGE: 00 24 00 P2 10 + old block(@5) + new block(@13). */
    private static byte[] combined() {
        byte[] apdu = new byte[]{0x00, 0x24, 0x00, P2, 0x10,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0};
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0x00); b.write(0x00);
        b.write(BM_FORMAT); b.write(BM_BLOCK); b.write(BM_LENFMT);
        b.write(0x05);                 // bInsertionOffsetOld
        b.write(0x0D);                 // bInsertionOffsetNew (13)
        b.write(PIN_MIN); b.write(PIN_MAX);
        b.write(0x03);                 // bConfirmPIN: confirm new + old present
        b.write(0x02);
        b.write(0x03);                 // bNumberMessage: old / new / confirm
        b.write(0x09); b.write(0x04);
        b.write(0x00); b.write(0x01); b.write(0x02);
        b.write(0x00); b.write(0x00); b.write(0x00);
        b.write(apdu.length & 0xFF); b.write(0); b.write(0); b.write(0);
        b.write(apdu, 0, apdu.length);
        return b.toByteArray();
    }

    private static int swOf(byte[] r) {
        if (r == null || r.length < 2) {
            System.out.println("short/null response: " + (r == null ? "null" : hex(r)));
            return -1;
        }
        return ((r[r.length - 2] & 0xFF) << 8) | (r[r.length - 1] & 0xFF);
    }

    private static String describe(int sw) {
        if (sw == 0x9000) return "SUCCESS - PIN changed";
        if ((sw & 0xFFF0) == 0x63C0) return "wrong PIN, " + (sw & 0x0F) + " tries left";
        if ((sw & 0xFF00) == 0x6B00) return "wrong parameters P1/P2";
        switch (sw) {
            case 0x6A88: return "reference data not found -> wrong P2 or SELECT app first";
            case 0x6A80: return "wrong data / PIN block format -> format/block bytes wrong";
            case 0x6983: return "PIN BLOCKED (needs PUK)";
            case 0x6982: return "security status not satisfied";
            case 0x6985: return "conditions of use not satisfied";
            case 0x6700: return "wrong length";
            case 0x6400: return "reader timeout";
            case 0x6401: return "user cancelled";
            case -1:     return "no/failed response";
            default:     return "unhandled - look up for your card";
        }
    }

    private static Map<Integer,Integer> discoverFeatures(Card card) throws CardException {
        byte[] tlv = card.transmitControlCommand(ctlCode(GET_FEATURE_REQUEST), new byte[0]);
        Map<Integer,Integer> map = new LinkedHashMap<Integer,Integer>();
        int i = 0;
        while (i + 2 <= tlv.length) {
            int tag = tlv[i] & 0xFF, len = tlv[i + 1] & 0xFF;
            if (len == 4 && i + 6 <= tlv.length) {
                int code = ((tlv[i+2]&0xFF)<<24)|((tlv[i+3]&0xFF)<<16)|((tlv[i+4]&0xFF)<<8)|(tlv[i+5]&0xFF);
                map.put(tag, code);
            }
            i += 2 + len;
        }
        return map;
    }

    private static String tagNames(Set<Integer> tags) {
        StringBuilder sb = new StringBuilder();
        for (Integer t : tags) {
            if (sb.length() > 0) sb.append(", ");
            if (t == FEATURE_VERIFY_PIN_DIRECT) sb.append("VERIFY_PIN_DIRECT");
            else if (t == FEATURE_MODIFY_PIN_DIRECT) sb.append("MODIFY_PIN_DIRECT");
            else sb.append(String.format("0x%02X", t));
        }
        return sb.toString();
    }

    private static CardTerminal pickTerminal(String[] args) throws CardException {
        List<CardTerminal> ts = TerminalFactory.getDefault().terminals().list();
        System.out.println("All readers:");
        for (CardTerminal t : ts)
            System.out.println("  - " + t.getName() + (t.isCardPresent() ? "   [card]" : ""));
        System.out.println();
        if (args != null && args.length > 0) {
            String want = args[0].toLowerCase();
            for (CardTerminal t : ts) if (t.getName().toLowerCase().contains(want)) return t;
        }
        for (CardTerminal t : ts) {
            String n = t.getName().toLowerCase();
            if (n.contains("cyberjack") || n.contains("reiner") || n.contains("sct")) return t;
        }
        for (CardTerminal t : ts) {
            String n = t.getName().toLowerCase();
            if (n.contains("uicc") || n.contains("microsoft")) continue;
            if (t.isCardPresent()) return t;
        }
        return null;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++) sb.append(String.format("%02X", b[i] & 0xFF));
        return sb.toString();
    }
}