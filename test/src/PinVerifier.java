import javax.smartcardio.*;
import java.util.Map;

public class PinVerifier {

    // ISO 7816-4 VERIFY APDU (CLA=0x00, INS=0x20)
    // Adjust P2 (0x81) to match your specific card's PIN Reference!
    private static final byte[] VERIFY_APDU = new byte[] {
            0x00, 0x20, 0x00, (byte)0x81, 0x00 // <-- Note the 0x00 Lc byte at the end
    };

    public static void main(String[] args) {
        try {
            Card card = CardUtils.connectToReader("cyberJack");
            Map<Integer, Integer> features = CardUtils.getReaderFeatures(card);

            if (!features.containsKey(CardUtils.FEATURE_VERIFY_PIN_DIRECT)) {
                System.out.println("Reader does not support secure PIN verification.");
                return;
            }

            int verifyControlCode = features.get(CardUtils.FEATURE_VERIFY_PIN_DIRECT);
            byte[] payload = buildVerifyPayload();

            System.out.println("Please enter PIN on the ReinerSCT keypad...");
            byte[] response = card.transmitControlCommand(verifyControlCode, payload);

            int sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
            System.out.printf("Response SW: %04X\n", sw);

            if (sw == 0x9000) {
                System.out.println("PIN Verified Successfully!");
            } else {
                System.out.println("PIN Verification Failed.");
            }

            card.disconnect(false);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] buildVerifyPayload() {
        byte[] controlStruct = new byte[] {
                0x00,        // bTimeOut (0 = default)
                0x00,        // bTimeOut2
                (byte)0x82,  // bmFormatString (0x82 = ASCII, try 0x02 for BCD if it fails)
                0x08,        // bmPINBlockString
                0x00,        // bmPINLengthFormat
                0x08, 0x04,  // wPINMaxExtraDigit = (min<<8)+max = 0x0408, stored LE as [max, min]
                0x02,        // bEntryValidationCondition (0x02 = OK key pressed)
                0x04,        // bNumberMessage (0x00 = Use default reader message)
                0x09,
                0x00,        // wLangId
                0x00,        // bMsgIndex
                0x00, 0x00, 0x00, // bTeoPrologue
                (byte)(VERIFY_APDU.length), 0x00, 0x00, 0x00 // ulDataLength - LITTLE ENDIAN!
        };
        return CardUtils.concat(controlStruct, VERIFY_APDU);
    }
}