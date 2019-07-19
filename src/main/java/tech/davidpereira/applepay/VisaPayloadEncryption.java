package tech.davidpereira.applepay;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Random;

public class VisaPayloadEncryption {

    private static final String CRYPT_ALGORITHM = "DESede";
    private static final String TRANSFORMATION = "DESede/CBC/NoPadding";

    // private static final byte[] KEY = Hex.decode("BB06591AE2A48628E803580576F73191");
    private static final byte[] KEY = Hex.decode("2315208C9110AD402315208C9110AD40");
    private static final byte[] IV = new byte[8];

    public static void main(String[] args) throws Exception {

        // String input = "pan=4171902981225164;expiry=0222;datetime=" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
        String input = "nonce=b9ef8f31;authcode=ZZLGEZ";

        System.out.println("Input: '" + input + "'");

        String blockInput = createBlocks(input);

        System.out.println("Input after block creation: '" + blockInput + "'");

        String hexInput = Hex.toHexString(blockInput.getBytes());

        System.out.println("Input in hex: '" + hexInput + "'");

        // do encrypt
        String encryptedText = encrypt(hexInput);

        // show result
        System.out.println("Encrypted text in Hex: '" + "MBPAC-1-FK-417190.1--TDEA-" + encryptedText + "'");
    }

    private static String createBlocks(String input) {
        Random random = new Random();

        StringBuilder sb = new StringBuilder("  ");

        for (int i = 0; i < 4; i++) {
            sb.append((char) (random.nextInt(94) + 33));
        }

        sb.append(input.length());
        sb.append(input);

        int padding = 8 - sb.length() % 8;

        if (padding != 8) {
            for (int i = 0; i < padding; i++) {
                sb.append("!");
            }
        }

        return sb.toString();
    }

    public static String encrypt(String text) throws Exception {
        // VISA key is 16 bytes, we have to convert to 24 bytes
        byte[] tdesKey = new byte[24];
        System.arraycopy(KEY, 0, tdesKey, 0, 16);
        System.arraycopy(KEY, 0, tdesKey, 16, 8);

        DESedeKeySpec keySpec = new DESedeKeySpec(tdesKey);
        SecretKey key = SecretKeyFactory.getInstance(CRYPT_ALGORITHM).generateSecret(keySpec);
        IvParameterSpec iv = new IvParameterSpec(IV);
        Cipher ecipher = Cipher.getInstance(TRANSFORMATION);
        ecipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] bytes = ecipher.doFinal(Hex.decode(text));
        return Hex.toHexString(bytes).toUpperCase();
    }

}