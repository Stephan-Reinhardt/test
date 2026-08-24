package test;

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

    private static final byte CLA        = (byte) 0x00;  // OLD CODE: CLA is 00, not B0
    private static final byte INS_VERIFY = (byte) 0x20;
    private static final byte INS_CHANGE = (byte) 0x24;

    // P2 selects WHICH pin (applet constants), not an ISO PIN reference
    private static final byte MASTER_PIN = (byte) 0x81;
    private static final byte USER_PIN   = (byte) 0x82;

    // ---- change this one line to work on the master PIN instead ----
    private static final byte PIN_TYPE   = USER_PIN;
    // ---------------------------------------------------------------

    // Format-2 PIN block: 8 bytes, first byte 0x20 (reader ORs in the length),
    // remaining bytes FF. Lc is 0x08 even though MAX_USER_PIN_LENGTH is 6.
    private static final byte PIN_BLOCK_HDR = (byte) 0x20;
    private static final byte PIN_FILL      = (byte) 0xFF;
    private static final int  LC            = 0x08;

    // exactly as the old working code
    private static final byte BM_FORMAT   = (byte) 0x82;
    private static final byte BM_BLOCK    = (byte) 0x04;
    private static final byte BM_LENFMT   = (byte) 0x04;  // OLD CODE: (0xF & 4)
    private static final byte PIN_MAX_D   = (byte) 0x08;  // wPINMaxExtraDigitMax
    private static final byte PIN_MIN_D   = (byte) 0x06;  // wPINMaxExtraDigitMin
    private static final byte B_ENTRY_VAL = (byte) 0x02;  // bEntryValidationCondition

    // ---- TEST CARD ONLY: PIN sent in software, no keypad ----
    private static final String TEST_OLD_PIN = "111111";
    private static final String TEST_NEW_PIN = "111111";
    // true  = plain APDU mode (no pinpad), uses the PINs above
    // false = secure pinpad mode
    private static final boolean PLAIN_MODE  = true;
    // ---------------------------------------------------------
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

                // ---- PLAIN MODE: hardcoded PINs, no keypad ----
                if (PLAIN_MODE) {
                    System.out.println("\n=== PLAIN APDU MODE (no pinpad, TEST CARD) ===");
                    System.out.println("old=" + TEST_OLD_PIN + "  new=" + TEST_NEW_PIN);
                    int sv = plain(INS_VERIFY, PIN_TYPE, TEST_OLD_PIN, "VERIFY plain");
                    if (sv == 0x9000) {
                        System.out.println("VERIFY ok -> applet is authenticated, now changing.");
                        int sc = plain(INS_CHANGE, PIN_TYPE, TEST_NEW_PIN, "CHANGE plain");
                        if (sc == 0x9000) {
                            System.out.println("\n*** PIN CHANGE SUCCEEDED via plain APDU. ***");
                            System.out.println("The applet command is correct; only the reader");
                            System.out.println("structure was the problem.");
                        }
                    } else {
                        System.out.println("VERIFY failed - see SW above.");
                        System.out.println("If 6A80/6700 -> the PIN block encoding below is wrong.");
                        System.out.println("Try ENCODING = 1 (ASCII) or 2 (BCD, no format-2 header).");
                    }
                    return;
                }

                // ---- STEP 1: VERIFY the old PIN at the keypad ----
                System.out.println("\n>>> Enter the OLD PIN at the keypad <<<");
                int sw1 = run(verifyCtl, buildVerify(), "VERIFY");
                if (sw1 != 0x9000) {
                    System.out.println("63Cx = wrong PIN typed. 6700 = Lc/length mismatch. 6A80 = PIN block format.");
                    return;
                }

                // ---- STEP 2: CHANGE the PIN at the keypad ----
                System.out.println("\n>>> Enter the NEW PIN, then the NEW PIN again <<<");
                // ---- CHANGE ATTEMPTS: leave ONE uncommented, recompile, run ----
                // Applet reads only the NEW pin at OFFSET_CDATA, so numMsg=2 / confirm=01.
                // Sweeping P1 and P2, since 6B80 = the applet rejects those.
                run(modifyCtl, buildChange(0x05, 2, 0x01, 1, 0x00, PIN_TYPE), "N1 P1=00 P2=82");
                //run(modifyCtl, buildChange(0x05, 2, 0x01, 1, 0x01, PIN_TYPE), "N2 P1=01 P2=82");
                //run(modifyCtl, buildChange(0x05, 2, 0x01, 1, 0x02, PIN_TYPE), "N3 P1=02 P2=82");
                //run(modifyCtl, buildChange(0x05, 2, 0x01, 1, PIN_TYPE, 0x00), "N4 P1=82 P2=00 (swapped)");
                //run(modifyCtl, buildChange(0x05, 2, 0x01, 1, 0x00, 0x01),     "N5 P1=00 P2=01");
                //run(modifyCtl, buildChange(0x05, 2, 0x01, 1, 0x00, 0x02),     "N6 P1=00 P2=02");
                // ---------------------------------------------------------------

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

    /** PIN block encoding for plain mode: 0=format-2, 1=ASCII digits, 2=BCD no header. */
    private static final int ENCODING = 0;

    /** Plain (non-pinpad) APDU transmit. PIN travels in software - TEST CARDS ONLY. */
    private static int plain(byte ins, byte p2, String pin, String label) {
        try {
            byte[] data = new byte[LC];
            if (ENCODING == 1) {                       // ASCII '1','1',... padded FF
                for (int i = 0; i < LC; i++)
                    data[i] = (i < pin.length()) ? (byte) pin.charAt(i) : PIN_FILL;
            } else if (ENCODING == 2) {                // packed BCD, no header, FF pad
                for (int i = 0; i < LC; i++) data[i] = PIN_FILL;
                for (int i = 0; i < pin.length(); i++) {
                    int d = pin.charAt(i) - '0';
                    int bi = i / 2;
                    if (i % 2 == 0) data[bi] = (byte) ((d << 4) | 0x0F);
                    else            data[bi] = (byte) ((data[bi] & 0xF0) | d);
                }
            } else {                                   // ISO format-2: 2N D D D D D D F...
                for (int i = 0; i < LC; i++) data[i] = PIN_FILL;
                data[0] = (byte) (0x20 | (pin.length() & 0x0F));
                for (int i = 0; i < pin.length(); i++) {
                    int d = pin.charAt(i) - '0';
                    int bi = 1 + i / 2;
                    if (i % 2 == 0) data[bi] = (byte) ((d << 4) | 0x0F);
                    else            data[bi] = (byte) ((data[bi] & 0xF0) | d);
                }
            }
            CommandAPDU c = new CommandAPDU(CLA & 0xFF, ins & 0xFF, 0x00, p2 & 0xFF, data);
            System.out.println("[" + label + "] enc=" + ENCODING + " apdu=" + hex(c.getBytes()));
            ResponseAPDU r = card.getBasicChannel().transmit(c);
            System.out.printf("[%s] SW=%04X -> %s%n", label, r.getSW(), describe(r.getSW()));
            return r.getSW();
        } catch (CardException e) {
            System.out.println("[" + label + "] transmit error: " + e.getMessage());
            return -1;
        }
    }

    /** Format-2 PIN block template: 20 FF FF FF FF FF FF FF (reader fills it in). */
    private static byte[] pinBlock() {
        byte[] blk = new byte[LC];
        blk[0] = PIN_BLOCK_HDR;
        for (int i = 1; i < LC; i++) blk[i] = PIN_FILL;
        return blk;
    }

    /** Mirrors the old app's createPINVerifyStructure(pinType). */
    private static byte[] buildVerify() {
        ByteArrayOutputStream a = new ByteArrayOutputStream();
        a.write(CLA); a.write(INS_VERIFY); a.write(0x00); a.write(PIN_TYPE); a.write(LC);
        byte[] blk = pinBlock();
        a.write(blk, 0, blk.length);
        byte[] apdu = a.toByteArray();

        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0x00);            // bTimeOut
        b.write(0x00);            // bTimeOut2
        b.write(BM_FORMAT);       // 0x82
        b.write(BM_BLOCK);        // 0x04
        b.write(BM_LENFMT);       // 0x04
        b.write(PIN_MAX_D);       // MAX first (as in the old code)
        b.write(PIN_MIN_D);       // then MIN
        b.write(B_ENTRY_VAL);     // bEntryValidationCondition
        b.write(0x01);            // bNumberMessage
        b.write(0x09); b.write(0x04);          // wLangId
        b.write(0x00);            // bMsgIndex
        b.write(0x00); b.write(0x00); b.write(0x00);   // bTeoPrologue
        b.write(apdu.length);     // ulDataLength (LE)
        b.write(0x00); b.write(0x00); b.write(0x00);
        b.write(apdu, 0, apdu.length);
        return b.toByteArray();
    }

    /**
     * MODIFY structure. Everything matches the proven VERIFY except the fields
     * unique to MODIFY, which are the parameters below.
     *
     * @param offNew  bInsertionOffsetNew (0x00 as OCR'd, or 0x05 = OFFSET_CDATA)
     * @param numMsg  bNumberMessage (2 = new+confirm, 3 = old+new+confirm)
     * @param confirm bConfirmPIN
     * @param msgBase first bMsgIndex value (old code appeared to use 1)
     */
    private static byte[] buildChange(int offNew, int numMsg, int confirm, int msgBase, int p1, int p2) {
        ByteArrayOutputStream a = new ByteArrayOutputStream();
        a.write(CLA); a.write(INS_CHANGE); a.write(p1); a.write(p2); a.write(LC);
        byte[] blk = pinBlock();
        a.write(blk, 0, blk.length);
        byte[] apdu = a.toByteArray();

        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0x00);            // bTimeOut
        b.write(0x00);            // bTimeOut2
        b.write(BM_FORMAT);       // 0x82   (proven by VERIFY)
        b.write(BM_BLOCK);        // 0x04   (proven by VERIFY)
        b.write(BM_LENFMT);       // 0x04   (proven by VERIFY)
        b.write(0x00);            // bInsertionOffsetOld
        b.write(offNew);          // bInsertionOffsetNew   <-- varies
        b.write(PIN_MAX_D);       // MAX first (proven by VERIFY)
        b.write(PIN_MIN_D);       // then MIN
        b.write(confirm);         // bConfirmPIN           <-- varies
        b.write(B_ENTRY_VAL);     // bEntryValidationCondition
        b.write(numMsg);          // bNumberMessage        <-- varies
        b.write(0x09); b.write(0x04);          // wLangId
        for (int i = 0; i < numMsg; i++) b.write(msgBase + i);   // bMsgIndex1..N
        b.write(0x00); b.write(0x00); b.write(0x00);   // bTeoPrologue
        b.write(apdu.length);     // ulDataLength (LE)
        b.write(0x00); b.write(0x00); b.write(0x00);
        b.write(apdu, 0, apdu.length);
        return b.toByteArray();
    }

    /**
     * The old working code reads SW1 at resp[0] and SW2 at resp[1] for pinpad
     * responses. Honour that for 2-byte buffers; fall back to the tail otherwise.
     */
    private static int swOf(byte[] r) {
        if (r == null) { System.out.println("  raw=null"); return -1; }
        System.out.println("  raw=" + hex(r) + "  len=" + r.length);
        if (r.length < 2) return -1;
        int head = ((r[0] & 0xFF) << 8) | (r[1] & 0xFF);
        int tail = ((r[r.length - 2] & 0xFF) << 8) | (r[r.length - 1] & 0xFF);
        int h1 = (head >> 8) & 0xFF;
        int sw = (h1 == 0x90 || (h1 >= 0x61 && h1 <= 0x6F)) ? head : tail;
        int sw1 = (sw >> 8) & 0xFF;
        if (sw1 != 0x90 && (sw1 < 0x61 || sw1 > 0x6F)) {
            System.out.println("  !! SW1=" + String.format("%02X", sw1)
                    + " is not a legal ISO status byte -> reader/driver result, not a card SW.");
        }
        return sw;
    }

    private static String describe(int sw) {
        if (sw == 0x9000) return "SUCCESS";
        if ((sw & 0xFFF0) == 0x63C0) return "wrong PIN, " + (sw & 0x0F) + " tries left";
        if ((sw & 0xFF00) == 0x6B00) return "wrong parameters P1/P2";
        switch (sw) {
            case 0x69AA: return "APPLET: user PIN not verified before change";
            case 0x69BB: return "APPLET: master PIN not verified before change";
            case 0x00AA: return "APPLET: user PIN not verified before change";
            case 0x00BB: return "APPLET: master PIN not verified before change";
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