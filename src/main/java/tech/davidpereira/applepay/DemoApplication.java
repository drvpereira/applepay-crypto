package tech.davidpereira.applepay;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import sun.security.x509.X509Key;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import static tech.davidpereira.applepay.ApplePayCryptoUtil.convertPrivateKey;
import static tech.davidpereira.applepay.ApplePayCryptoUtil.convertPublicKey;

public class DemoApplication {

    public static void main(String[] args) throws Exception {

        //test();

        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        String dataToEncrypt = "Data to encrypt";

        System.out.printf("Message to encrypt: %s\n", dataToEncrypt);
        System.out.printf("Message to encrypt in hex: %s\n\n", Hex.toHexString(dataToEncrypt.getBytes()));

        // Reading Apple public certificate from file
        X509Certificate certificate = ApplePayCryptoUtil.getCertificate("src/main/resources/UC6InMemory.pem");
        X509Key applePublicKey = (X509Key) certificate.getPublicKey();

        System.out.printf("Apple server static public key (in uncompressed format): %s\n\n", Hex.toHexString(applePublicKey.getEncoded()).replaceAll("3059301306072a8648ce3d020106082a8648ce3d030107034200", ""));

        // Generating an Ephemeral Key Pair
        //KeyPair ephemeralKeyPair = ApplePayCryptoUtil.generateEphemeralKeyPair();
        //PrivateKey ephemeralPrivateKey = ephemeralKeyPair.getPrivate();
        //PublicKey ephemeralPublicKey = ephemeralKeyPair.getPublic();

        byte[] ephemeralPublicKeyBytes = Hex.decode("0499a6f42e83ea4f150a78780ffb562c9cdb9b7507bc5d28cbfbf8cc3ef0af68b36e60cb10db69127830f7f899492017089e3b73c83fcf0ebdf2c06b613c3f88b7");
        byte[] ephemeralPrivateKeyBytes = Hex.decode("7eee47dee108a08edd2bcd2bb762a543ca23ea96c9af09ad54beb9fa3ce1a026");

        PublicKey ephemeralPublicKey = convertPublicKey(ephemeralPublicKeyBytes);
        System.out.printf("Ephemeral public key: %s\n", Hex.toHexString(ephemeralPublicKey.getEncoded()).replaceAll("3059301306072a8648ce3d020106082a8648ce3d030107034200", ""));
        PrivateKey ephemeralPrivateKey = convertPrivateKey(ephemeralPrivateKeyBytes);
        System.out.printf("Ephemeral private key: %s\n\n", Hex.toHexString(ephemeralPrivateKey.getEncoded()));

        // A shared secret must be created using Apple's public key AND our ephemeral private key. Apple must be able
        // to generate the same shared secret using their private key and our ephemeral public key.
        byte[] sharedSecret = ApplePayCryptoUtil.getSharedSecret(applePublicKey, ephemeralPrivateKey);
        System.out.printf("Shared Secret in hex: %s\n\n", Hex.toHexString(sharedSecret));

        byte[] otherInfo = ApplePayCryptoUtil.getOtherInfo(ephemeralPublicKeyBytes);
        System.out.println("Other info: " + Hex.toHexString(otherInfo));



        // Now it is time to create a shared key from the shared secret.
        byte[] sharedKey = ApplePayCryptoUtil.getSharedKey(sharedSecret, otherInfo);
        System.out.printf("AES key in hex: %s\n\n", Hex.toHexString(sharedKey));

        byte[] encryptedData = ApplePayCryptoUtil.encryptData(sharedKey, dataToEncrypt.getBytes());
        System.out.printf("Encrypted data in hex: %s\n\n", Hex.toHexString(encryptedData));

        byte[] decryptedData = ApplePayCryptoUtil.decryptData(sharedKey, encryptedData);
        System.out.printf("Decrypted message: %s\n", new String(decryptedData));

    }

}
