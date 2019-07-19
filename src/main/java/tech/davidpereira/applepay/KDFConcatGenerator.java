package tech.davidpereira.applepay;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.KDFParameters;

/**
 * Basic KDF generator for derived keys and ivs
 * <br>
 * http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf
 */
public class KDFConcatGenerator implements DerivationFunction {

    private int counterStart = 1;
    private Digest digest;
    private byte[] shared;
    byte[] otherInfo;

    /**
     * Construct a KDF Parameters generator.
     * <p>
     *
     * @param digest       the digest to be used as the source of derived keys.
     */
    public KDFConcatGenerator(Digest digest, byte[] otherInfo) {
        this.digest = digest;
        this.otherInfo = otherInfo;
    }

    public void init(DerivationParameters param) {

        if (param instanceof KDFParameters) {
            KDFParameters p = (KDFParameters) param;
            shared = p.getSharedSecret();
        } else {
            throw new IllegalArgumentException("KDF parameters required for KDFConcatGenerator");
        }
    }

    /**
     * return the underlying digest.
     */
    public Digest getDigest() {
        return digest;
    }

    /**
     * fill len bytes of the output buffer with bytes generated from
     * the derivation function.
     *
     * @throws IllegalArgumentException if the size of the request will cause an overflow.
     * @throws DataLengthException      if the out buffer is too small.
     */
    public int generateBytes(byte[] out, int outOff, int len) throws DataLengthException, IllegalArgumentException {
        if ((out.length - len) < outOff) {
            throw new DataLengthException("output buffer too small");
        }

        long oBytes = len;
        int outLen = digest.getDigestSize();

        //
        // this is at odds with the standard implementation, the
        // maximum value should be hBits * (2^32 - 1) where hBits
        // is the digest output size in bits. We can't have an
        // array with a long index at the moment...
        //
        if (oBytes > ((2L << 32) - 1)) {
            throw new IllegalArgumentException("Output length too large");
        }

        int cThreshold = (int) ((oBytes + outLen - 1) / outLen);

        byte[] dig = new byte[digest.getDigestSize()];

        int counter = counterStart;

        for (int i = 0; i < cThreshold; i++) {
            // 5.1 Compute Hash_i = H(counter || Z || OtherInfo).
            digest.update((byte) (counter >> 24));
            digest.update((byte) (counter >> 16));
            digest.update((byte) (counter >> 8));
            digest.update((byte) counter);
            digest.update(shared, 0, shared.length);
            digest.update(otherInfo, 0, otherInfo.length);

            digest.doFinal(dig, 0);

            if (len > outLen) {
                System.arraycopy(dig, 0, out, outOff, outLen);
                outOff += outLen;
                len -= outLen;
            } else {
                System.arraycopy(dig, 0, out, outOff, len);
            }

            counter++;
        }

        digest.reset();

        return len;
    }

}