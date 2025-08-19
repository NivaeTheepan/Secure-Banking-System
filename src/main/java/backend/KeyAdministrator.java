package backend;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * KeyAdministrator class to handle key generation, retrieval, and encoding
 * for encryption and MAC (Message Authentication Code) operations.
 * 
 * The class ensures the creation of cryptographic keys for secure communication.
 */
public class KeyAdministrator {
    private static SecretKey masterSecretKey; // Master secret key used to derive other keys
    private static SecretKeySpec encryptKey;  // Encryption key used for AES encryption
    private static SecretKeySpec macKey;      // MAC key used for HMAC-SHA256

    /**
     * Method to generate encryption and MAC keys from given SecretKeys.
     * 
     * @param encryptionKey SecretKey used for encryption (AES)
     * @param macKey SecretKey used for MAC (HmacSHA256)
     */
    public static void generateKeys(SecretKey encryptionKey, SecretKey macKey) {
        KeyAdministrator.encryptKey = new SecretKeySpec(encryptionKey.getEncoded(), "AES");
        KeyAdministrator.macKey = new SecretKeySpec(macKey.getEncoded(), "HmacSHA256");
    }

    /**
     * Synchronized method to generate the master secret key for AES encryption.
     * It uses a secure random number generator and then calls `obtainKeys()` 
     * to derive the encryption and MAC keys from the master key.
     */
    public static synchronized void generateMasterSecret() {
        try {
            // Initialize AES key generator with 256-bit key size and secure random generator
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256, new SecureRandom());
            masterSecretKey = keyGen.generateKey(); // Generate master secret key
            obtainKeys(masterSecretKey); // Derive encryption and MAC keys from master key
        } catch (NoSuchAlgorithmException e) {
            // Exception handling if AES algorithm is not available
            throw new RuntimeException("Error generating Master Secret key", e);
        }
    }

    /**
     * Private method to derive encryption and MAC keys from the master key.
     * It generates a SHA-256 hash of the master key and splits it into two parts:
     * one for AES encryption and one for HMAC SHA-256.
     * 
     * @param masterKey SecretKey to derive the encryption and MAC keys from
     */
    private static void obtainKeys(SecretKey masterKey) {
        try {
            byte[] masterKeyBytes = masterKey.getEncoded(); // Get the encoded bytes of the master key

            // Use SHA-256 to hash the master key
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] fullHash = sha256.digest(masterKeyBytes); // Get the hash of the master key

            // Split the hash into two 128-bit parts: one for AES and one for HMAC-SHA256
            encryptKey = new SecretKeySpec(Arrays.copyOfRange(fullHash, 0, 16), "AES");
            macKey = new SecretKeySpec(Arrays.copyOfRange(fullHash, 16, 32), "HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            // Exception handling if SHA-256 is not available
            throw new RuntimeException("Error deriving keys", e);
        }
    }

    /**
     * Method to get the encryption key (AES). If the key does not exist, it will generate the master secret key.
     * 
     * @return The AES encryption key
     */
    public static SecretKey getEncryptKey() {
        if (encryptKey == null) {
            generateMasterSecret(); // Generate keys if encryption key is not available
        }
        return encryptKey;
    }

    /**
     * Method to get the MAC key (HMAC-SHA256). If the key does not exist, it will generate the master secret key.
     * 
     * @return The HMAC-SHA256 key
     */
    public static SecretKey getMacKey() {
        if (macKey == null) {
            generateMasterSecret(); // Generate keys if MAC key is not available
        }
        return macKey;
    }

    /**
     * Method to get the Base64-encoded encryption key (AES).
     * 
     * @return Base64-encoded string representing the AES encryption key
     */
    public static String getEncodedEncryptKey() {
        return Base64.getEncoder().encodeToString(getEncryptKey().getEncoded());
    }

    /**
     * Method to get the Base64-encoded MAC key (HMAC-SHA256).
     * 
     * @return Base64-encoded string representing the HMAC-SHA256 key
     */
    public static String getEncodedMacKey() {
        return Base64.getEncoder().encodeToString(getMacKey().getEncoded());
    }

    /**
     * Method to decode a Base64-encoded key back into a SecretKey object.
     * 
     * @param encodedKey Base64-encoded string representing the key
     * @param algorithm Algorithm used for the key (e.g., "AES", "HmacSHA256")
     * @return The decoded SecretKey
     */
    public static SecretKey decodeKeyFromString(String encodedKey, String algorithm) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey); // Decode from Base64
        return new SecretKeySpec(decodedKey, algorithm); // Return the key as a SecretKeySpec
    }
}
