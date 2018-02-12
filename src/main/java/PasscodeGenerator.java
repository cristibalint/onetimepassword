import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class PasscodeGenerator {

    private static final String ALGORITHM = "HmacSHA1";
    private static final int LENGTH = 6;

    public String getPasscode(String base32Secret) throws NoSuchAlgorithmException, InvalidKeyException {
        Base32 base32 = new Base32();
        byte[] secret = base32.decode(base32Secret.replace(" ", ""));

        long time = System.currentTimeMillis() / 1000 / 30;
        byte[] data = toBigEndianByteArray(time);


        SecretKeySpec signKey = new SecretKeySpec(secret, ALGORITHM);
        Mac mac = Mac.getInstance(ALGORITHM);
        mac.init(signKey);

        // Processing the instant of time and getting the encrypted data.
        byte[] hash = mac.doFinal(data);

        // Building the validation code performing dynamic truncation
        // (RFC4226, 5.3. Generating an HOTP value)
        int offset = hash[hash.length - 1] & 0xF;

        // We are using a long because Java hasn't got an unsigned integer type
        // and we need 32 unsigned bits).
        long truncatedHash = 0;

        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;

            // Java bytes are signed but we need an unsigned integer:
            // cleaning off all but the LSB.
            truncatedHash |= (hash[offset + i] & 0xFF);
        }

        // Clean bits higher than the 32nd (inclusive) and calculate the
        // module with the maximum validation code value.
        truncatedHash = truncate(truncatedHash);

        // Returning the validation code to the caller.
        return padLeftWith0(truncatedHash);
    }

    private byte[] toBigEndianByteArray(long time) {
        byte[] data = new byte[8];
        for (int i = 8; i-- > 0; time >>= 8) {
            data[i] = (byte) time;
        }
        return data;
    }

    private long truncate(long truncatedHash) {
            truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= Math.pow(10, LENGTH);
        return truncatedHash;
    }

    private String padLeftWith0(long number) {
        return String.format("%0" + LENGTH + "d", number);
    }
}
