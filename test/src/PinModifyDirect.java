import javax.smartcardio.*;
import java.io.ByteArrayOutputStream;
import java.util.*;

/**
 * Change a card PIN on a class-3 reader (cyberJack) as VERIFY(old) + CHANGE(new).
 *
 * Two secure operations on ONE held handle (beginExclusive), which is the correct
 * form of the classic two-step flow and avoids any session-state loss between steps.
 *
 * The card-specific values are overridable WITHOUT recompiling:
 *   java -Dp2=81 -Dpinmin=6 -Dpinmax=8 PinModifyDirect cyberJack
 *   -Dp2      PIN reference (hex), default 01   <-- the value most likely wrong
 *   -Dpinmin  min PIN digits (dec), default 6
 *   -Dpinmax  max PIN digits (dec), default 8
 *   -Dformat  bmFormatString (hex), default 02
 *   -Dblock   bmPINBlockString (hex), default 08
 *   -Dlenfmt  bmPINLengthFormat (hex), default 00
 *
 * Java 8 compatible. Run from a console so you see the output.
 */
public class PinModifyDirect {

    private static int ctlCode(int code) { return 0x310000 | (code << 2); }
    private static final int GET_FEATURE_REQUEST      = 3400;
    private static final int FEATURE_VERIFY_PIN_DIRECT = 0x06;
    private static final int FEATURE_MODIFY_PIN_DIRECT = 0x07;

    // --- card-specific, overridable via -D properties ---
    private static final byte P2        = (byte) hexProp("p2", 0x01);
    private static final int  PIN_MIN   = decProp("pinmin", 6);
    private static final int  PIN_MAX   = decProp("pinmax", 8);
    private static final byte BM_FORMAT = (byte) hexProp("format", 0x02);
    private static final byte BM_BLOCK  = (byte) hexProp("block", 0x08);
    private static final byte BM_LENFMT = (byte) hexProp("lenfmt", 0x00);

    public static void main(String[] args) throws Exception {
        CardTerminal terminal = pickTerminal(args);
        if (terminal == null) {
            System.out.println("No cyberJack reader found. Try: java PinModifyDirect cyberJack");
            return;
        }
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
                if (vCtl == null || mCtl == null) {
                    System.out.println("Reader is missing VERIFY or MODIFY direct support.");
                    return;
                }
                System.out.printf("Params: P2=%02X  PIN %d..%d  format=%02X block=%02X lenfmt=%02X%n",
                        P2 & 0xFF, PIN_MIN, PIN_MAX, BM_FORMAT & 0xFF, BM_BLOCK & 0xFF, BM_LENFMT & 0xFF);

                // STEP 1 - VERIFY old PIN. Its SW tells us whether P2 is correct.
                System.out.println("\n>>> STEP 1: enter the OLD PIN at the keypad <<<");
                int sw1 = swOf(card.transmitControlCommand(vCtl, buildVerify()));
                System.out.printf("VERIFY  SW=%04X -> %s%n", sw1, describe(sw1));
                if (sw1 != 0x9000) {
                    System.out.println("Stop here: with a correct old PIN this should be 9000.");
                    System.out.println("If it is 6A88 / 6B.. -> P2 is wrong (try -Dp2=81, 02, 00) or SELECT the app first.");
                    System.out.println("If it is 63Cx -> P2 is RIGHT, you just mistyped the old PIN.");
                    return;
                }

                // STEP 2 - CHANGE new PIN only (P1=01); old PIN already verified above.
                System.out.println("\n>>> STEP 2: enter the NEW PIN, then the NEW PIN again <<<");
                int sw2 = swOf(card.transmitControlCommand(mCtl, buildModifyNewOnly()));
                System.out.printf("CHANGE  SW=%04X -> %s%n", sw2, describe(sw2));
            } finally {
                card.endExclusive();
            }
        } finally {
            card.disconnect(false);
        }
    }

    /** PIN_VERIFY_STRUCTURE + VERIFY apdu (00 20 00 P2 08 + 8-byte block). */
    private static byte[] buildVerify() {
        byte[] apdu = new byte[]{0x00, 0x20, 0x00, P2, 0x08, 0,0,0,0,0,0,0,0};
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0x00); b.write(0x00);                 // bTimerOut, bTimerOut2
        b.write(BM_FORMAT); b.write(BM_BLOCK); b.write(BM_LENFMT);
        b.write(PIN_MIN); b.write(PIN_MAX);           // wPINMaxExtraDigit (min,max)
        b.write(0x02);                                // bEntryValidationCondition
        b.write(0x01);                                // bNumberMessage
        b.write(0x09); b.write(0x04);                 // wLangId 0x0409
        b.write(0x00);                                // bMsgIndex
        b.write(0x00); b.write(0x00); b.write(0x00);  // bTeoPrologue
        b.write(apdu.length & 0xFF); b.write(0); b.write(0); b.write(0); // ulDataLength LE
        b.write(apdu, 0, apdu.length);
        return b.toByteArray();
    }

    /** PIN_MODIFY_STRUCTURE + CHANGE apdu, new PIN only (00 24 01 P2 08 + 8-byte block). */
    private static byte[] buildModifyNewOnly() {
        byte[] apdu = new byte[]{0x00, 0x24, 0x01, P2, 0x08, 0,0,0,0,0,0,0,0}; // P1=01
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0x00); b.write(0x00);                 // bTimerOut, bTimerOut2
        b.write(BM_FORMAT); b.write(BM_BLOCK); b.write(BM_LENFMT);
        b.write(0x00);                                // bInsertionOffsetOld (none)
        b.write(0x05);                                // bInsertionOffsetNew (after 5-byte header)
        b.write(PIN_MIN); b.write(PIN_MAX);           // wPINMaxExtraDigit (min,max)
        b.write(0x01);                                // bConfirmPIN: confirm new, no old
        b.write(0x02);                                // bEntryValidationCondition
        b.write(0x02);                                // bNumberMessage: new + confirm
        b.write(0x09); b.write(0x04);                 // wLangId 0x0409
        b.write(0x00); b.write(0x01);                 // bMsgIndex1, bMsgIndex2
        b.write(0x00); b.write(0x00); b.write(0x00);  // bTeoPrologue
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
        if ((sw & 0xFFF0) == 0x63C0) return "wrong PIN, " + (sw & 0x0F) + " tries left (P2 is correct!)";
        if ((sw & 0xFF00) == 0x6B00) return "wrong parameters P1/P2 -> wrong PIN reference (P2) or change mode (P1)";
        switch (sw) {
            case 0x6A88: return "reference data (PIN) not found -> wrong P2, or SELECT the application first";
            case 0x6A86: return "wrong P1/P2";
            case 0x6A80: return "wrong data / PIN block format -> format/block bytes wrong";
            case 0x6983: return "PIN BLOCKED (needs PUK)";
            case 0x6982: return "security status not satisfied";
            case 0x6985: return "conditions of use not satisfied";
            case 0x6700: return "wrong length";
            case 0x6400: return "reader timeout";
            case 0x6401: return "user cancelled at keypad";
            case -1:     return "no card response";
            default:     return "unhandled - look up this SW for your card";
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