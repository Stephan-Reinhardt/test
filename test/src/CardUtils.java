import javax.smartcardio.*;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class CardUtils {
    // OS-specific IOCTL for CM_IOCTL_GET_FEATURE_REQUEST
    private static final int IOCTL_GET_FEATURE_REQUEST =
            System.getProperty("os.name").toLowerCase().contains("win") ? 0x00313520 : 0x42000D48;

    public static final int FEATURE_VERIFY_PIN_DIRECT = 0x06;
    public static final int FEATURE_MODIFY_PIN_DIRECT = 0x07;

    public static Card connectToReader(String readerNameHint) throws CardException {
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();

        for (CardTerminal terminal : terminals) {
            if (terminal.getName().toLowerCase().contains(readerNameHint.toLowerCase())) {
                System.out.println("Connecting to: " + terminal.getName());
                return terminal.connect("*");
            }
        }
        throw new CardException("Reader matching '" + readerNameHint + "' not found.");
    }

    public static Map<Integer, Integer> getReaderFeatures(Card card) throws CardException {
        Map<Integer, Integer> features = new LinkedHashMap<>();
        byte[] response = card.transmitControlCommand(IOCTL_GET_FEATURE_REQUEST, new byte[0]);

        int i = 0;
        while (i + 6 <= response.length) {
            int tag = response[i] & 0xFF;
            // Value is a 4-byte integer (Big Endian in this TLV response)
            int controlCode = ((response[i + 2] & 0xFF) << 24) |
                    ((response[i + 3] & 0xFF) << 16) |
                    ((response[i + 4] & 0xFF) << 8) |
                    (response[i + 5] & 0xFF);
            features.put(tag, controlCode);
            i += 6;
        }
        return features;
    }

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}