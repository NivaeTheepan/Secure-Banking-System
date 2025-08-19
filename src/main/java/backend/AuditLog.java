package backend;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * AuditLog class records user actions (transactions) in both plain text
 * and encrypted log files for auditing purposes.
 * 
 * @author lalit
 */
public class AuditLog {
    // Path to the plain text log file where actions will be stored in an unencrypted form
    private static final String PLAIN_LOG = "logs/audit_log.txt";
    // Path to the encrypted log file where actions will be stored in an encrypted form
    private static final String ENCRYPTED_LOG = "logs/audit_log_encrypted.txt";
    // Secret key used for encrypting the log entries (must be the correct length for AES encryption)
    private static final String SECRET = "AuditEncryptKeys";
    
    /**
     * Records a transaction in both plain text and encrypted formats.
     * 
     * @param username The username of the user performing the action.
     * @param action The action the user performed.
     */
    public static void recordTransaction(String username, String action) {
        // Get the current timestamp in the format "yyyy-MM-dd HH:mm:ss"
        String timeStamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        // Combine timestamp, username, and action to create the log entry
        String logEntry = timeStamp + " - " + username + " - " + action;

        // Write the log entry to the plain text log file
        try (FileWriter writer = new FileWriter(PLAIN_LOG, true)) {
            writer.write(logEntry + "\n"); // Write log entry and a newline character
        } catch (IOException e) {
            // Handle any IO exceptions that occur while writing to the plain log
            System.out.println("Error writing to plain log: " + e.getMessage());
        }

        // Write the encrypted version of the log entry to the encrypted log file
        try (FileWriter writer = new FileWriter(ENCRYPTED_LOG, true)) {
            writer.write(encrypt(logEntry) + "\n"); // Write the encrypted log entry and a newline character
        } catch (Exception e) {
            // Handle any exceptions that occur while writing to the encrypted log
            System.out.println("Error writing to encrypted log: " + e.getMessage());
        }
    }

    /**
     * Encrypts the provided string using AES encryption.
     * 
     * @param strToEncrypt The string to be encrypted.
     * @return The encrypted string in Base64 format.
     * @throws Exception If any encryption errors occur.
     */
    private static String encrypt(String strToEncrypt) throws Exception {
        // Create a secret key for AES encryption using the provided SECRET string
        SecretKeySpec secretKey = new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "AES");
        // Initialize the cipher for AES encryption
        Cipher cipher = Cipher.getInstance("AES");

        // Initialize the cipher with the encryption mode and the secret key
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        // Encrypt the string
        byte[] encrypted = cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8));
        // Return the encrypted string as a Base64 encoded string
        return Base64.getEncoder().encodeToString(encrypted);
    }
}
