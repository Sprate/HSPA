import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;


public class BytesToHex {

    /*public static String fromBytesToHex(byte[] resultBytes) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < resultBytes.length; i++) {
            if (Integer.toHexString(0xFF & resultBytes[i]).length() == 1) {
                builder.append("0").append(Integer.toHexString(0xFF & resultBytes[i]));
            } else {
                builder.append(Integer.toHexString(0xFF & resultBytes[i]));
            }
        }
        return builder.toString();
    }
    */
    public static String fromBytesToHex(byte[] bytes)
            throws DecoderException {
        return Hex.encodeHexString(bytes);
    }

    public static byte[] fromHexToBytes(String hexString)
            throws DecoderException {
        return Hex.decodeHex(hexString.toCharArray());
    }
}