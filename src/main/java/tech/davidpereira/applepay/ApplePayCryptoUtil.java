package tech.davidpereira.applepay;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

public class ApplePayCryptoUtil {

    public static X509Certificate getCertificate(String certificateFile) throws Exception {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        return (X509Certificate) fact.generateCertificate(new FileInputStream(certificateFile));
    }

    public static KeyPair generateEphemeralKeyPair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(256);
        //g.initialize(new ECGenParameterSpec("secp256r1")); // secp256r1 is an alias for the
                                                                    // Elliptic Curve 1.2.840.10045.3.1.7
                                                                    // which is used to create the ephemeral key pair
        return g.generateKeyPair();
    }

    public static byte[] getSharedSecret(Key applePublicKey, Key ephemeralPrivateKey) throws Exception {
        KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH", "BC");
        ecdhV.init(ephemeralPrivateKey); // Ephemeral private key
        ecdhV.doPhase(applePublicKey,true); // Apple public key
        return ecdhV.generateSecret();
    }

    // Derived according to the Concatenation Format speciﬁed in section 5.8.1.2.1 in NIST SP 800-56A
    public static byte[] getOtherInfo(byte[] partyV) throws Exception {
        String algorithmId = (char) 0x0D + "id-aes256-GCM"; // This is the algorithm ID
        String partyUInfo = "Apple"; // This is the PartyUInfo according to Apple document

        // Concatenate and convert to array of bytes
        byte[] kdfPrefix = (algorithmId + partyUInfo).getBytes("ASCII");

        // Create an array of bytes large enough for AlgorithmID + PartyUInfo + PartyVInfo
        byte[] otherInfo = new byte[kdfPrefix.length + partyV.length];

        // Copy all info to the new array
        System.arraycopy(kdfPrefix, 0, otherInfo, 0, kdfPrefix.length);
        System.arraycopy(partyV, 0, otherInfo, kdfPrefix.length, partyV.length);
        return otherInfo;
    }

    // NIST key derivation function w/ Apple Pay specific parameters
    public static byte[] getSharedKey(byte[] sharedSecret, byte[] otherInfo) throws Exception {
        KDFConcatGenerator kdf = new KDFConcatGenerator(new SHA256Digest(), otherInfo);
        kdf.init(new KDFParameters(sharedSecret, null));

        SHA256Digest digest = (SHA256Digest) kdf.getDigest();

        byte[] aesKey = new byte[32]; // This is the shared key created from the shared secret
        kdf.generateBytes(aesKey, 0, aesKey.length);

        return aesKey;
    }

    // Apple Pay uses an 0s for the IV (initialization vector)
    public static final byte[] IV = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    public static byte[] encryptData(byte[] symmetricKeyBytes, byte[] dataBytes) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKeyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC"); // AES, GCM mode, No padding

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new GCMParameterSpec(128, IV)); // GCM authentication tag of 128 bits + initialization vector of 12 null bytes (0x00)

        return cipher.doFinal(dataBytes);
    }

    public static byte[] decryptData(byte[] symmetricKeyBytes, byte[] dataBytes) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKeyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new GCMParameterSpec(128, IV));
        return cipher.doFinal(dataBytes);
    }

    public static PrivateKey convertPrivateKey(byte[] privateKeyByteArray) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("EC", "BC");

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", spec.getCurve(), spec.getG(), spec.getN());
        PrivateKey privateKey =  factory.generatePrivate(new ECPrivateKeySpec(new BigInteger(Hex.toHexString(privateKeyByteArray), 16), params));

        return privateKey;
    }

    public static PublicKey convertPublicKey(byte[] publicKeyByteArray) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("EC", "BC");

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", spec.getCurve(), spec.getG(), spec.getN());
        ECPoint publicPoint =  ECPointUtil.decodePoint(params.getCurve(), publicKeyByteArray);

        return factory.generatePublic(new ECPublicKeySpec(publicPoint, params));
    }

}
