package backend;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * MessageEncryption class provides various cryptographic methods for
 * encrypting and decrypting data using RSA, AES, generating MACs (Message Authentication Codes),
 * and hashing passwords securely.
 * 
 * It supports both asymmetric encryption (RSA) and symmetric encryption (AES).
 */
public class MessageEncryption {
    private static final String HMAC_ALGO = "HmacSHA256"; // HMAC algorithm used for MAC generation

    /**
     * Encrypts the given data using RSA encryption with the provided public key.
     * 
     * @param data The data to encrypt
     * @param publicKey The public key to use for encryption
     * @return Base64 encoded string of the encrypted data
     */
    public static String encryptRSA(String data, PublicKey publicKey) {
        try {
            // Create RSA cipher and initialize it for encryption
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            // Encrypt the data and return as a Base64 encoded string
            return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting with RSA", e); // Exception handling for errors
        }
    }

    /**
     * Decrypts the given encrypted data using RSA decryption with the provided private key.
     * 
     * @param encryptedData The encrypted data to decrypt
     * @param privateKey The private key to use for decryption
     * @return Decrypted string
     */
    public static String decryptRSA(String encryptedData, PrivateKey privateKey) {
        try {
            // Check if the encrypted data is empty or null
            if (encryptedData == null || encryptedData.isEmpty()) {
                throw new IllegalArgumentException("ERROR: Attempted to decrypt an empty message.");
            }

            // Create RSA cipher and initialize it for decryption
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            // Decrypt the data and return as a string
            return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedData)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting with RSA", e); // Exception handling for errors
        }
    }

    /**
     * Encrypts the given data using AES encryption in CBC mode with PKCS5 padding.
     * A random IV (Initialization Vector) is generated for encryption.
     * 
     * @param data The data to encrypt
     * @param secretKey The secret AES key used for encryption
     * @return A Base64 encoded string of the IV and the encrypted data
     */
    public static String encryptAES(String data, SecretKey secretKey) {
        try {
            // Create AES cipher in CBC mode with PKCS5 padding
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // Generate a random IV (Initialization Vector)
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            // Initialize cipher for encryption
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            // Encrypt the data
            byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

            // Return both the IV and encrypted data as Base64 encoded strings
            return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting with AES", e); // Exception handling for errors
        }
    }

    /**
     * Decrypts the given encrypted data using AES decryption in CBC mode with PKCS5 padding.
     * The IV is extracted from the encrypted data.
     * 
     * @param encryptedData The encrypted data to decrypt
     * @param secretKey The secret AES key used for decryption
     * @return Decrypted string
     */
    public static String decryptAES(String encryptedData, SecretKey secretKey) {
        try {
            // Split the encrypted data into IV and cipher text
            String[] parts = encryptedData.split(":");
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] cipherText = Base64.getDecoder().decode(parts[1]);

            // Create AES cipher and initialize it for decryption
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            // Decrypt and return the data as a string
            return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting with AES", e); // Exception handling for errors
        }
    }

    /**
     * Encrypts the AES secret key using RSA encryption with the provided public key.
     * 
     * @param secretKey The AES key to encrypt
     * @param publicKey The public key to use for RSA encryption
     * @return Base64 encoded string of the encrypted AES key
     */
    public static String encryptAESKey(SecretKey secretKey, PublicKey publicKey) {
        try {
            // Create RSA cipher and initialize it for encryption
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            // Encrypt the AES key and return as a Base64 encoded string
            return Base64.getEncoder().encodeToString(cipher.doFinal(secretKey.getEncoded()));
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting AES key with RSA", e); // Exception handling for errors
        }
    }

    /**
     * Decrypts the given encrypted AES key using RSA decryption with the provided private key.
     * 
     * @param encryptedKey The encrypted AES key to decrypt
     * @param privateKey The private key to use for RSA decryption
     * @return The decrypted AES key as a SecretKey object
     */
    public static SecretKey decryptAESKey(String encryptedKey, PrivateKey privateKey) {
        try {
            // Create RSA cipher and initialize it for decryption
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            // Decrypt the AES key and return it as a SecretKey object
            byte[] decodedKey = cipher.doFinal(Base64.getDecoder().decode(encryptedKey));
            return new SecretKeySpec(decodedKey, "AES");
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting AES key with RSA", e); // Exception handling for errors
        }
    }
    
    /**
     * Hashes the given password using the SHA-256 hashing algorithm.
     * 
     * @param password The password to hash
     * @return The Base64 encoded string of the hashed password
     */
    public static String hashPassword(String password) {
        try {
            // Create SHA-256 message digest instance
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = md.digest(password.getBytes());
            // Return the hashed password as a Base64 encoded string
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing password", e); // Exception handling for errors
        }
    }

    /**
     * Verifies if the given password matches the hashed password.
     * 
     * @param password The plain-text password to verify
     * @param hashedPassword The hashed password to compare against
     * @return True if the passwords match, false otherwise
     */
    public static boolean verifyPassword(String password, String hashedPassword) {
        // Compare the hashed value of the password with the stored hashed password
        return hashPassword(password).equals(hashedPassword);
    }

    /**
     * Generates a Message Authentication Code (MAC) for the given data using HMAC-SHA256.
     * 
     * @param data The data to generate MAC for
     * @param macKey The secret key used for HMAC
     * @return Base64 encoded string of the generated MAC
     */
    public static String generateMac(String data, SecretKey macKey) {
        try {
            // Create HMAC instance using the specified algorithm
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(macKey);
            byte[] macBytes = mac.doFinal(data.getBytes());
            // Return the MAC as a Base64 encoded string
            return Base64.getEncoder().encodeToString(macBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error generating MAC", e); // Exception handling for errors
        }
    }

    /**
     * Verifies if the given data's MAC matches the received MAC.
     * 
     * @param data The data to verify the MAC for
     * @param receivedMac The MAC to verify against
     * @param macKey The secret key used for MAC generation
     * @return True if the MACs match, false otherwise
     */
    public static boolean verifyMac(String data, String receivedMac, SecretKey macKey) {
        // Generate expected MAC and compare with the received MAC
        String expectedMac = generateMac(data, macKey);
        return expectedMac.equals(receivedMac);
    }
}
