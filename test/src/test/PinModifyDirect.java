import javax.smartcardio.*;
import java.io.ByteArrayOutputStream;
import java.util.*;

/**
 * PIN change for the ADWHCryptoCard applet on a J3H145 (JCOP v3) card,
 * via a cyberJack class-3 reader using secure PIN entry.
 *
 * Applet AID : 01 02 03 04 05 06 07 08 09 00 00
 * CLA        : 0xB0   (applet-specific -- NOT 0x00)
 * INS VERIFY : 0x20
 * INS CHANGE : 0x24
 *
 * Flow: SELECT applet -> VERIFY old PIN (pinpad) -> CHANGE PIN (pinpad).
 *
 *   javac PinModifyDirect.java
 *   java  PinModifyDirect
 *
 * Java 8 compatible. Run from a console.
 */
public class PinModifyDirect {

    // ===================== APPLET / CARD CONSTANTS =====================
    private static final byte[] AID = {
            (byte)0x01,(byte)0x02,(byte)0x03,(byte)0x04,(byte)0x05,(byte)0x06,
            (byte)0x07,(byte)0x08,(byte)0x09,(byte)0x00,(byte)0x00 };

    private static final byte CLA        = (byte) 0xB0;  // applet CLA
    private static final byte INS_VERIFY = (byte) 0x20;
    private static final byte INS_CHANGE = (byte) 0x24;

    private static final byte P1_VERIFY  = (byte) 0x00;
    private static final byte P2_VERIFY  = (byte) 0x00;  // try 0x81 if 6A88/6B00
    private static final byte P1_CHANGE  = (byte) 0x00;  // 0x00 = old+new, 0x01 = new only
    private static final byte P2_CHANGE  = (byte) 0x00;  // try 0x81 if 6A88/6B00

    private static final int  PIN_MIN    = 4;            // adjust to the applet's OwnerPIN
    private static final int  PIN_MAX    = 8;
    private static final byte BM_FORMAT  = (byte) 0x82;  // from the old app
    private static final byte BM_BLOCK   = (byte) 0x04;  // from the old app
    private static final byte BM_LENFMT  = (byte) 0x00;
    private static final byte PIN_FILL   = (byte) 0xFF;  // old app filled with FF
    // ===================================================================

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

                // ---- STEP 0: SELECT the applet (this was missing all along) ----
                CommandAPDU sel = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AID);
                System.out.println("\nSELECT " + hex(sel.getBytes()));
                ResponseAPDU sr = card.getBasicChannel().transmit(sel);
                System.out.printf("SELECT SW=%04X -> %s%n", sr.getSW(), describe(sr.getSW()));
                if (sr.getSW() != 0x9000) {
                    System.out.println("Applet not selected. 6A82 = applet not installed on this card.");
                    return;
                }

                // ---- STEP 1: VERIFY the old PIN at the keypad ----
                System.out.println("\n>>> Enter the OLD PIN at the keypad <<<");
                int sw1 = run(verifyCtl, buildVerify(), "VERIFY");
                if (sw1 != 0x9000) {
                    System.out.println("VERIFY failed. If 6A88/6B00 -> try P2_VERIFY = 0x81.");
                    System.out.println("If 63Cx -> P2 correct, wrong PIN typed.");
                    return;
                }

                // ---- STEP 2: CHANGE the PIN at the keypad ----
                System.out.println("\n>>> Enter the NEW PIN, then the NEW PIN again <<<");
                run(modifyCtl, buildChange(), "CHANGE");

            } finally {
                card.endExclusive();
            }
        } finally {
            card.disconnect(false);
        }
    }

    private static int run(int ctl, byte[] struct, String label) {
        System.out.println("[" + label + "] struct=" + hex(struct));
        try {
            int sw = swOf(card.transmitControlCommand(ctl, struct));
            System.out.printf("[%s] SW=%04X -> %s%n", label, sw, describe(sw));
            return sw;
        } catch (CardException e) {
            System.out.println("[" + label + "] READER ERROR: " + e.getMessage());
            return -1;
        }
    }

    /** PIN_VERIFY_STRUCTURE + apdu B0 20 P1 P2 08 <block>. */
    private static byte[] buildVerify() {
        byte f = PIN_FILL;
        byte[] apdu = {CLA, INS_VERIFY, P1_VERIFY, P2_VERIFY, 0x08, f,f,f,f,f,f,f,f};
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0x00); b.write(0x00);               // bTimeOut, bTimeOut2
        b.write(BM_FORMAT); b.write(BM_BLOCK); b.write(BM_LENFMT);
        b.write(PIN_MIN); b.write(PIN_MAX);         // wPINMaxExtraDigit
        b.write(0x02);                              // bEntryValidationCondition
        b.write(0x01);                              // bNumberMessage
        b.write(0x09); b.write(0x04);               // wLangId
        b.write(0x00);                              // bMsgIndex
        b.write(0x00); b.write(0x00); b.write(0x00);// bTeoPrologue
        b.write(apdu.length & 0xFF); b.write(0); b.write(0); b.write(0);
        b.write(apdu, 0, apdu.length);
        return b.toByteArray();
    }

    /**
     * PIN_MODIFY_STRUCTURE + apdu B0 24 P1 P2 Lc <blocks>.
     * P1_CHANGE 0x00 -> old block @5 and new block @13 (Lc=0x10)
     * P1_CHANGE 0x01 -> new block @5 only (Lc=0x08)
     */
    private static byte[] buildChange() {
        boolean withOld = (P1_CHANGE == 0x00);
        int lc = withOld ? 0x10 : 0x08;
        byte f = PIN_FILL;

        ByteArrayOutputStream a = new ByteArrayOutputStream();
        a.write(CLA); a.write(INS_CHANGE); a.write(P1_CHANGE); a.write(P2_CHANGE); a.write(lc);
        for (int i = 0; i < lc; i++) a.write(f);
        byte[] apdu = a.toByteArray();

        int offOld = withOld ? 5 : 0;
        int offNew = withOld ? 13 : 5;
        int numMsg = withOld ? 3 : 2;

        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0x00); b.write(0x00);
        b.write(BM_FORMAT); b.write(BM_BLOCK); b.write(BM_LENFMT);
        b.write(offOld);                            // bInsertionOffsetOld
        b.write(offNew);                            // bInsertionOffsetNew
        b.write(PIN_MIN); b.write(PIN_MAX);
        b.write(withOld ? 0x03 : 0x01);             // bConfirmPIN
        b.write(0x02);                              // bEntryValidationCondition
        b.write(numMsg);                            // bNumberMessage
        b.write(0x09); b.write(0x04);               // wLangId
        for (int i = 0; i < numMsg; i++) b.write(i + 1);  // bMsgIndex1..N (old app used 1,2)
        b.write(0x00); b.write(0x00); b.write(0x00);// bTeoPrologue
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
            case 0x6D00: return "INS not supported by the selected applet";
            case 0x6E00: return "CLA not supported -> wrong class byte";
            case 0x6A82: return "file/applet not found -> AID not installed on this card";
            case 0x6A88: return "reference data not found -> wrong P2";
            case 0x6A80: return "wrong data / PIN block format";
            case 0x6983: return "PIN blocked (needs PUK/unblock)";
            case 0x6982: return "security status not satisfied -> PIN not verified";
            case 0x6985: return "conditions of use not satisfied";
            case 0x6700: return "wrong length";
            case 0x6400: return "reader timeout";
            case 0x6401: return "user cancelled";
            case -1:     return "no/failed response";
            default:     return "unhandled - check the applet source";
        }
    }

    private static Map<Integer,Integer> discoverFeatures(Card card) throws CardException {
        byte[] tlv = card.transmitControlCommand(ctlCode(GET_FEATURE_REQUEST), new byte[0]);
        Map<Integer,Integer> map = new LinkedHashMap<Integer,Integer>();
        int i = 0;
        while (i + 2 <= tlv.length) {
            int tag = tlv[i] & 0xFF, len = tlv[i + 1] & 0xFF;
            if (len == 4 && i + 6 <= tlv.length) {
                int code = ((tlv[i+2]&0xFF)<<24)|((tlv[i+3]&0xFF)<<16)
                        | ((tlv[i+4]&0xFF)<<8) | (tlv[i+5]&0xFF);
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