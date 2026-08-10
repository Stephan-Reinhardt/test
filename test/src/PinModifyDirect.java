import javax.smartcardio.*;
import java.io.ByteArrayOutputStream;
import java.util.*;

/**
git  * Change a card PIN on a class-3 reader (cyberJack).
 *
 * Two modes (-Dmode=...):
 *   combined (DEFAULT) : one MODIFY_PIN_DIRECT, CHANGE P1=00, reader collects
 *                        OLD + NEW + confirm. The cyberJack's usual path.
 *   split              : VERIFY_PIN_DIRECT(old) then MODIFY_PIN_DIRECT(new only, P1=01),
 *                        both on one held handle.
 *
 * Card-specific values overridable without recompiling:
 *   -Dp2=81      PIN reference (hex)          [required for your card]
 *   -Dpinmin=6   min PIN digits (dec)
 *   -Dpinmax=8   max PIN digits (dec)
 *   -Dformat=02  bmFormatString (hex)
 *   -Dblock=08   bmPINBlockString (hex)
 *   -Dlenfmt=00  bmPINLengthFormat (hex)
 *   -Dmode=combined|split
 *
 * Example:  java -Dp2=81 PinModifyDirect cyberJack
 * Java 8 compatible. Run from a console.
 */
public class PinModifyDirect {

    private static int ctlCode(int code) { return 0x310000 | (code << 2); }
    private static final int GET_FEATURE_REQUEST       = 3400;
    private static final int FEATURE_VERIFY_PIN_DIRECT = 0x06;
    private static final int FEATURE_MODIFY_PIN_DIRECT = 0x07;

    private static final byte P2        = (byte) hexProp("p2", 0x81);
    private static final int  PIN_MIN   = decProp("pinmin", 6);
    private static final int  PIN_MAX   = decProp("pinmax", 8);
    private static final byte BM_FORMAT = (byte) hexProp("format", 0x02);
    private static final byte BM_BLOCK  = (byte) hexProp("block", 0x08);
    private static final byte BM_LENFMT = (byte) hexProp("lenfmt", 0x00);
    private static final String MODE    = System.getProperty("mode", "combined");

    public static void main(String[] args) throws Exception {
        CardTerminal terminal = pickTerminal(args);
        if (terminal == null) { System.out.println("No cyberJack reader found."); return; }
        System.out.println("Using reader: " + terminal.getName());

        Card card = terminal.connect("*");
        try {
            System.out.println("ATR: " + hex(card.getATR().getBytes()));
            card.beginExclusive();
            try {
                Map<Integer,Integer> features = discoverFeatures(card);
                System.out.println("Features: " + tagNames(features.keySet()));
                Integer vCtl = features.get(FEATURE_VERIFY_PIN_DIRECT);
                Integer mCtl = features.get(FEATURE_MODIFY_PIN_DIRECT);
                if (mCtl == null) { System.out.println("No MODIFY_PIN_DIRECT."); return; }
                System.out.printf("Mode=%s  P2=%02X  PIN %d..%d  format=%02X block=%02X lenfmt=%02X%n",
                        MODE, P2 & 0xFF, PIN_MIN, PIN_MAX, BM_FORMAT & 0xFF, BM_BLOCK & 0xFF, BM_LENFMT & 0xFF);

                if ("split".equalsIgnoreCase(MODE)) {
                    if (vCtl == null) { System.out.println("No VERIFY_PIN_DIRECT for split mode."); return; }
                    System.out.println("\n>>> STEP 1: enter the OLD PIN <<<");
                    if (runSecure(card, vCtl, buildVerify(), "VERIFY") != 0x9000) {
                        System.out.println("Stop: VERIFY must be 9000 before the change.");
                        return;
                    }
                    System.out.println("\n>>> STEP 2: enter NEW PIN, then NEW PIN again <<<");
                    runSecure(card, mCtl, buildModifyNewOnly(), "CHANGE");
                } else {
                    System.out.println("\n>>> Enter OLD PIN, then NEW PIN, then NEW PIN again <<<");
                    runSecure(card, mCtl, buildModifyCombined(), "CHANGE");
                }
            } finally {
                card.endExclusive();
            }
        } finally {
            card.disconnect(false);
        }
    }

    private static int runSecure(Card card, int ctl, byte[] struct, String label) {
        System.out.println(label + " struct: " + hex(struct));
        try {
            int sw = swOf(card.transmitControlCommand(ctl, struct));
            System.out.printf("%s  SW=%04X -> %s%n", label, sw, describe(sw));
            return sw;
        } catch (CardException e) {
            String m = e.getMessage();
            Throwable c = e.getCause();
            System.out.println(label + "  READER/DRIVER ERROR: " + m + (c != null ? " (" + c.getMessage() + ")" : ""));
            System.out.println("  -> this is a reader-level abort, not a card SW.");
            System.out.println("  -> check: both NEW entries identical? length within " + PIN_MIN + ".." + PIN_MAX + "?");
            System.out.println("  -> if it persists on 'combined', try -Dmode=split; and vice versa.");
            return -1;
        }
    }

    /** PIN_VERIFY_STRUCTURE + VERIFY apdu (00 20 00 P2 08 + 8-byte block). */
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

    /** Combined change: CHANGE P1=00, OLD (offset 5) + NEW (offset 13), confirm new. */
    private static byte[] buildModifyCombined() {
        byte[] apdu = new byte[]{0x00, 0x24, 0x00, P2, 0x10,
                0,0,0,0,0,0,0,0,    // old block @5
                0,0,0,0,0,0,0,0};   // new block @13
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0x00); b.write(0x00);
        b.write(BM_FORMAT); b.write(BM_BLOCK); b.write(BM_LENFMT);
        b.write(0x05);                 // bInsertionOffsetOld
        b.write(0x0D);                 // bInsertionOffsetNew (13)
        b.write(PIN_MIN); b.write(PIN_MAX);
        b.write(0x03);                 // bConfirmPIN: confirm new + old present
        b.write(0x02);                 // bEntryValidationCondition
        b.write(0x03);                 // bNumberMessage: old / new / confirm
        b.write(0x09); b.write(0x04);
        b.write(0x00); b.write(0x01); b.write(0x02);
        b.write(0x00); b.write(0x00); b.write(0x00);
        b.write(apdu.length & 0xFF); b.write(0); b.write(0); b.write(0);
        b.write(apdu, 0, apdu.length);
        return b.toByteArray();
    }

    /** New-only change: CHANGE P1=01, NEW (offset 5), confirm new. Requires prior VERIFY. */
    private static byte[] buildModifyNewOnly() {
        byte[] apdu = new byte[]{0x00, 0x24, 0x01, P2, 0x08, 0,0,0,0,0,0,0,0};
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0x00); b.write(0x00);
        b.write(BM_FORMAT); b.write(BM_BLOCK); b.write(BM_LENFMT);
        b.write(0x00);                 // bInsertionOffsetOld (none)
        b.write(0x05);                 // bInsertionOffsetNew
        b.write(PIN_MIN); b.write(PIN_MAX);
        b.write(0x01);                 // bConfirmPIN: confirm new only
        b.write(0x02);
        b.write(0x02);                 // bNumberMessage: new + confirm
        b.write(0x09); b.write(0x04);
        b.write(0x00); b.write(0x01);
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
        if (sw == 0x9000) return "SUCCESS";
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

    private static int hexProp(String k, int def) {
        String v = System.getProperty(k);
        if (v == null) return def;
        try { v = v.trim(); if (v.startsWith("0x")) v = v.substring(2); return Integer.parseInt(v, 16); }
        catch (Exception e) { return def; }
    }
    private static int decProp(String k, int def) {
        String v = System.getProperty(k);
        if (v == null) return def;
        try { return Integer.parseInt(v.trim()); } catch (Exception e) { return def; }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++) sb.append(String.format("%02X", b[i] & 0xFF));
        return sb.toString();
    }
}