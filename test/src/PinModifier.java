import javax.smartcardio.*;
import java.util.Map;

public class PinModifier {

    // ISO 7816-4 CHANGE REFERENCE DATA APDU (CLA=0x00, INS=0x24)
    // P1=0x00 means user will enter BOTH Old and New PIN.
    private static final byte[] MODIFY_APDU = new byte[] {
            0x00, 0x24, 0x00, (byte)0x81, 0x00
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
                0x04,        // bmPINBlockString
                0x00,        // bmPINLengthFormat
                0x00,        // bInsertionOffsetOld (Card dependent, usually 0)
                0x00,        // bInsertionOffsetNew (Card dependent, usually 0)
                0x04, 0x00,  // wPINMaxExtraDigit (Min 4) - LITTLE ENDIAN!
                0x08, 0x00,  // wPINMaxExtraDigit (Max 8) - LITTLE ENDIAN!
                0x03,        // bConfirmPIN (0x03 = prompt new PIN and confirm)
                0x02,        // bEntryValidationCondition (OK key)
                0x00,        // bNumberMessage (0x00 = Use default reader messages)
                0x07, 0x04,  // wLangId (de-DE)
                0x00,        // bMsgIndex1 (Prompt for Old PIN)
                0x00,        // bMsgIndex2 (Prompt for New PIN)
                0x00,        // bMsgIndex3 (Prompt for Confirmation)
                0x00, 0x00, 0x00, // bTeoPrologue
                (byte)(MODIFY_APDU.length), 0x00, 0x00, 0x00 // ulDataLength
        };
        return CardUtils.concat(controlStruct, MODIFY_APDU);
    }
}