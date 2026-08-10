import javax.smartcardio.*;
import java.util.Map;

public class PinModifier {

    // ISO 7816-4 CHANGE REFERENCE DATA APDU (CLA=0x00, INS=0x24)
    // P1=0x00 means user will enter BOTH Old and New PIN.
    // Case 1 APDU: CLA INS P1 P2 only - no trailing Lc/Le byte. The reader
    // builds and appends the actual data field itself (confirmed against
    // REINER SCT's own modify_pin_direct.cpp sample, which sends exactly
    // 4 bytes here).
    private static final byte[] MODIFY_APDU = new byte[] {
            0x00, 0x24, 0x00, (byte)0x81
    };

    public static void main(String[] args) {
        try {
            Card card = CardUtils.connectToReader("cyberJack");
            Map<Integer, Integer> features = CardUtils.getReaderFeatures(card);

            if (!features.containsKey(CardUtils.FEATURE_MODIFY_PIN_DIRECT)) {
                System.out.println("Reader does not support secure PIN modification.");
                return;
            }

            int modifyControlCode = features.get(CardUtils.FEATURE_MODIFY_PIN_DIRECT);
            byte[] payload = buildModifyPayload();

            System.out.println("Follow the prompts on the ReinerSCT keypad (Old PIN -> New PIN -> Confirm)...");
            byte[] response = card.transmitControlCommand(modifyControlCode, payload);

            StringBuilder rawHex = new StringBuilder();
            for (byte b : response) {
                rawHex.append(String.format("%02X ", b));
            }
            System.out.println("Raw response (" + response.length + " bytes): " + rawHex.toString().trim());

            int sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
            System.out.printf("Response SW: %04X\n", sw);

            if (sw == 0x9000) {
                System.out.println("PIN Changed Successfully!");
            } else {
                System.out.println("PIN Change Failed.");
            }

            card.disconnect(false);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] buildModifyPayload() {
        byte[] controlStruct = new byte[] {
                0x00,        // bTimeOut
                0x00,        // bTimeOut2
                (byte)0x82,  // bmFormatString (ASCII)
                0x08,        // bmPINBlockString: 8-byte block, matches PinVerifier (4 bytes is too small to hold a 6-digit ASCII PIN)
                0x00,        // bmPINLengthFormat
                0x00,        // bInsertionOffsetOld
                0x00,        // bInsertionOffsetNew (matches REINER SCT sample: reader appends old+new itself)
                0x06, 0x06,  // wPINMaxExtraDigit = (min<<8)+max = 0x0408, stored LE as [max, min]
                0x03,        // bConfirmPIN: bit0=confirm new PIN, bit1=request current/old PIN first
                0x02,        // bEntryValidationCondition (OK key)
                0x09,        // bNumbe2rMessage (0x00 = Use default reader messages)
                0x04,
                0x01,  // wLangId (de-DE)
                0x00,        // bMsgIndex1 (Prompt for Old PIN)
                0x00,        // bMsgIndex2 (Prompt for New PIN)
                0x00,        // bMsgIndex3 (Prompt for Confirmation)
                0x00, 0x00, 0x00, // bTeoPrologue (BYTE[3] per spec - was truncated to 2 bytes)
                (byte)(MODIFY_APDU.length), 0x00, 0x00, 0x00 // ulDataLength
        };
        return CardUtils.concat(controlStruct, MODIFY_APDU);
    }
}