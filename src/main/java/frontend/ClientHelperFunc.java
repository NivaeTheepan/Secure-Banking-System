package frontend;

import backend.AuditLog;
import backend.KeyAdministrator;
import backend.MessageEncryption;
import frontend.Server;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Base64;
import java.util.HashMap;
import javax.crypto.SecretKey;

/*
 * ClientHelperFunc class handles the interaction with each client connected to the server.
 * It listens for client requests (login, register, account deletion), processes them, 
 * and sends appropriate responses.
 */

public class ClientHelperFunc implements Runnable {
    // Socket connection and I/O streams
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;
    // Static maps to store users and balances information
    private static final HashMap<String, String> usersList = Server.getUsers();
    private static final HashMap<String, Double> balancesList = Server.getBalances();

    // Constructor that accepts the socket for the client connection
    public ClientHelperFunc(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try {
            // Set up input and output streams
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);

            // Generate master secret key for encryption
            KeyAdministrator.generateMasterSecret();

            // Keep handling client requests until disconnected
            while (true) {
                String choice = in.readLine();  // Read client choice
                if (choice == null) {
                    break;  // Exit loop if client disconnects
                }

                // Switch statement to handle different client requests based on the choice received
                switch (choice) {
                    case "1":
                        loginHandler();  // Handle login request
                        break;
                    case "2":
                        registerHandler();  // Handle registration request
                        break;
                    case "3":
                        accountDeletionHandler();  // Handle account deletion request
                        break;
                    case "4":
                        socket.close();  // Close socket connection and return
                        return;
                    default:
                        out.println("Invalid option.");  // Handle invalid input
                }
            }
        } catch (IOException e) {
            // Handle any I/O errors during the client-server interaction
            System.err.println("Error handling client: " + e.getMessage());
        } finally {
            // Ensure the socket is closed when done
            try {
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                }
            } catch (IOException e) {
                System.err.println("Error closing socket: " + e.getMessage());
            }
        }
    }

    // Method to handle client login
    private void loginHandler() throws IOException {
        String username = in.readLine();  // Read username from client
        String password = in.readLine();  // Read password from client

        // If username or password is invalid, notify the client
        if (username == null || password == null) {
            out.println("Invalid credentials.");
            return;
        }

        // Check if the credentials are valid
        if (usersList.containsKey(username) && MessageEncryption.verifyPassword(password, usersList.get(username))) {
            out.println("Authentication successful!");  // Notify client of successful authentication

            // Get encryption and MAC keys for secure communication
            SecretKey encryptionKey = KeyAdministrator.getEncryptKey();
            SecretKey macKey = KeyAdministrator.getMacKey();

            // Send the encrypted keys to the client
            out.println(Base64.getEncoder().encodeToString(encryptionKey.getEncoded()));
            out.println(Base64.getEncoder().encodeToString(macKey.getEncoded()));

            // Log the login transaction and proceed to the transaction handler
            AuditLog.recordTransaction(username, "LOGIN SUCCESS");
            transactionHandler(username);
        } else {
            out.println("Invalid credentials.");  // If authentication fails
            AuditLog.recordTransaction(username, "LOGIN FAILED");
        }
    }

    // Method to handle client registration
    private void registerHandler() throws IOException {
        String username = in.readLine();  // Read username from client
        String password = in.readLine();  // Read password from client
        String depositStr = in.readLine();  // Read initial deposit from client

        // Check if any information is missing
        if (username == null || password == null || depositStr == null) {
            out.println("Registration failed. Missing information.");
            return;
        }

        // Check if the username is already taken
        if (usersList.containsKey(username)) {
            out.println("Username already taken.");
            return;
        }

        try {
            double initDeposit = Double.parseDouble(depositStr);  // Parse deposit amount
            if (initDeposit < 0) {
                out.println("Deposit amount must be at least $0.");
                return;
            }

            // Hash the password and store the user info
            String hashPwd = MessageEncryption.hashPassword(password);
            usersList.put(username, hashPwd);
            balancesList.put(username, initDeposit);
            Server.saveDatabase();  // Save user data to the database

            out.println("Registration successful!");  // Notify client of successful registration
            AuditLog.recordTransaction(username, "ACCOUNT CREATED with $" + initDeposit);  // Log transaction
        } catch (NumberFormatException e) {
            out.println("Invalid deposit amount.");  // Handle invalid deposit format
        }
    }

    // Method to handle account deletion
    private void accountDeletionHandler() throws IOException {
        String username = in.readLine();  // Read username from client
        String password = in.readLine();  // Read password from client

        // Check if any information is missing
        if (username == null || password == null) {
            out.println("Invalid credentials.");
            return;
        }

        // Check if the credentials are valid for account deletion
        if (usersList.containsKey(username) && MessageEncryption.verifyPassword(password, usersList.get(username))) {
            // Remove user data from server
            usersList.remove(username);
            balancesList.remove(username);
            Server.saveDatabase();

            out.println("Account deleted successfully.");  // Notify client
            AuditLog.recordTransaction(username, "ACCOUNT DELETED");  // Log transaction
        } else {
            out.println("Invalid credentials.");  // Handle invalid credentials for deletion
        }
    }

    // Method to securely send an encrypted response to the client
    private void transmitEncryptedResponse(String message, SecretKey encryptionKey, SecretKey macKey) {
        try {
            // Encrypt the message and generate MAC
            String encrypted = MessageEncryption.encryptAES(message, encryptionKey);
            String mac = MessageEncryption.generateMac(message, macKey);

            // Send the encrypted message and MAC to the client
            out.println(encrypted);
            out.println(mac);
        } catch (Exception e) {
            System.err.println("[SERVER] Error sending secure response: " + e.getMessage());
            out.println("Error generating response.");
        }
    }

    // Method to handle client transactions like deposit, withdrawal, and balance check
    private void transactionHandler(String username) throws IOException {
        SecretKey encryptKey = KeyAdministrator.getEncryptKey();  // Get encryption key
        SecretKey macKey = KeyAdministrator.getMacKey();  // Get MAC key

        try {
            while (true) {
                if (socket.isClosed()) {
                    System.out.println("[SERVER] Client socket closed. Exiting transaction handler.");
                    return;
                }

                // Read encrypted request and MAC from client
                String encryptRequest = in.readLine();
                if (encryptRequest == null) {
                    System.out.println("[SERVER] Client disconnected.");
                    return;
                }

                String macReceived = in.readLine();
                if (macReceived == null) {
                    System.out.println("[SERVER] Client disconnected during MAC transmission.");
                    return;
                }

                // Decrypt request and verify MAC
                String query;
                try {
                    query = MessageEncryption.decryptAES(encryptRequest, encryptKey);

                    if (!MessageEncryption.verifyMac(query, macReceived, macKey)) {
                        System.err.println("[SERVER] MAC verification failed.");
                        transmitEncryptedResponse("MAC verification failed.", encryptKey, macKey);
                        continue;
                    }
                } catch (Exception e) {
                    System.err.println("[SERVER] Error decrypting or verifying request: " + e.getMessage());
                    transmitEncryptedResponse("Decryption/MAC verification failed.", encryptKey, macKey);
                    continue;
                }

                // Process the transaction based on the client's request
                String[] parts = query.split(":");
                if (parts.length < 1) {
                    transmitEncryptedResponse("Invalid command format.", encryptKey, macKey);
                    continue;
                }

                String instruction = parts[0].toLowerCase();
                String reply;

                try {
                    switch (instruction) {
                        case "deposit":
                            if (parts.length < 2) {
                                reply = "Invalid deposit amount.";
                                break;
                            }
                            double depositAmount = Double.parseDouble(parts[1]);
                            if (depositAmount <= 0) {
                                reply = "Deposit amount must be positive.";
                            } else {
                                balancesList.put(username, balancesList.get(username) + depositAmount);
                                reply = "Deposit successful! New Balance: $" + balancesList.get(username);
                                AuditLog.recordTransaction(username, "DEPOSIT: $" + depositAmount);
                                Server.saveDatabase();
                            }
                            break;

                        case "withdraw":
                            if (parts.length < 2) {
                                reply = "Invalid withdrawal amount.";
                                break;
                            }
                            double withdrawAmount = Double.parseDouble(parts[1]);
                            if (withdrawAmount <= 0) {
                                reply = "Withdrawal amount must be positive.";
                            } else if (withdrawAmount > balancesList.get(username)) {
                                reply = "Insufficient funds.";
                            } else {
                                balancesList.put(username, balancesList.get(username) - withdrawAmount);
                                reply = "Withdrawal successful! New Balance: $" + balancesList.get(username);
                                AuditLog.recordTransaction(username, "WITHDRAWAL: $" + withdrawAmount);
                                Server.saveDatabase();
                            }
                            break;

                        case "balance":
                            reply = "Current Balance: $" + balancesList.get(username);
                            AuditLog.recordTransaction(username, "BALANCE CHECK");
                            break;

                        case "exit":
                            System.out.println("[SERVER] Client exiting.");
                            return;

                        default:
                            reply = "Invalid command.";
                            break;
                    }
                    transmitEncryptedResponse(reply, encryptKey, macKey);  // Send encrypted response to client
                } catch (NumberFormatException e) {
                    transmitEncryptedResponse("Invalid amount format.", encryptKey, macKey);  // Handle invalid number format
                }
            }
        } finally {
            // Clean up after the transaction session ends
            System.out.println("[SERVER] Ending transaction session for user: " + username);
        }
    }
}
