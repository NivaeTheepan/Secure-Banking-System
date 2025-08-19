package frontend;

import backend.MessageEncryption;
import backend.KeyAdministrator;
import com.formdev.flatlaf.FlatDarkLaf;

import javax.swing.*;
import java.awt.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.crypto.SecretKey;

/**
 * AccountDashboard is the graphical user interface (GUI) for the user's account dashboard.
 * It allows the user to check balance, deposit, withdraw, and log out of the application.
 * 
 * The dashboard supports secure communication with the server using encryption and MAC (Message Authentication Code).
 * 
 * @author lalit
 */
public class AccountDashboard extends JFrame {
    private JTextArea infoPanel; // Panel to display information such as balance and transaction results
    private Client client; // The client object responsible for communication with the server
    private String username; // The username of the logged-in user
    private SecretKey encryptKey; // AES encryption key for encrypting data
    private SecretKey macKey; // HMAC key for message authentication

    /**
     * Constructor initializes the account dashboard for the specified user.
     * Sets up the encryption and MAC keys, and applies a dark theme to the UI.
     * 
     * @param client The client object for communicating with the server.
     * @param username The username of the logged-in user.
     */
    public AccountDashboard(Client client, String username) {
        this.client = client;
        this.username = username;
        this.encryptKey = KeyAdministrator.getEncryptKey(); // Get the AES encryption key
        this.macKey = KeyAdministrator.getMacKey(); // Get the HMAC key

        // Set dark theme for the UI
        try {
            UIManager.setLookAndFeel(new FlatDarkLaf()); // Apply the dark theme using FlatDarkLaf
        } catch (Exception e) {
            e.printStackTrace();
        }

        initializeUI(); // Initialize the user interface
    }

    /**
     * Initializes the user interface by setting up the window, buttons, and info panel.
     * Creates buttons for checking balance, deposit, withdraw, and logging out.
     */
    private void initializeUI() {
        setTitle("Welcome, " + username); // Set the window title to include the username
        setSize(480, 420); // Set the size of the window
        setLayout(new BorderLayout()); // Use BorderLayout for organizing components
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE); // Close the window when the user closes it
        getContentPane().setBackground(new Color(45, 45, 45)); // Set the background color to dark

        // Button panel for the main options (balance check, deposit, withdraw, logout)
        JPanel buttonPanel = new JPanel(new GridLayout(4, 1, 15, 15)); // Grid layout with 4 buttons vertically
        buttonPanel.setBackground(new Color(45, 45, 45)); // Dark background for the panel
        buttonPanel.setBorder(new EmptyBorder(30, 40, 20, 40)); // Set padding around the buttons

        // Add buttons to the button panel with specific actions and colors
        buttonPanel.add(createModernButton("Check Balance", e -> balanceUserCheck(), new Color(52, 152, 219)));
        buttonPanel.add(createModernButton("Deposit", e -> transactionHandler("deposit"), new Color(46, 204, 113)));
        buttonPanel.add(createModernButton("Withdraw", e -> transactionHandler("withdraw"), new Color(241, 196, 15)));
        buttonPanel.add(createModernButton("Logout", e -> logout(), new Color(231, 76, 60)));

        add(buttonPanel, BorderLayout.CENTER); // Add button panel to the center of the window

        // Info panel to display messages (e.g., balance, transaction results)
        infoPanel = new JTextArea(4, 30);
        infoPanel.setEditable(false); // Make the panel non-editable
        infoPanel.setLineWrap(true); // Enable line wrapping
        infoPanel.setWrapStyleWord(true); // Wrap lines at word boundaries
        infoPanel.setFont(new Font("Verdana", Font.PLAIN, 13)); // Set font style and size
        infoPanel.setBackground(new Color(60, 63, 65)); // Set a dark background color
        infoPanel.setForeground(Color.WHITE); // Set text color to white
        infoPanel.setCaretColor(Color.WHITE); // Set the caret color to white (text cursor)
        infoPanel.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(90, 90, 90), 1, true), // Add border around the info panel
                new EmptyBorder(10, 10, 10, 10) // Padding inside the panel
        ));

        // Scrollable container for the info panel
        JScrollPane scrollPane = new JScrollPane(infoPanel);
        scrollPane.setBorder(new EmptyBorder(10, 30, 20, 30)); // Set padding around the scroll pane
        scrollPane.getViewport().setBackground(new Color(60, 63, 65)); // Set scroll pane background to dark
        add(scrollPane, BorderLayout.SOUTH); // Add scroll pane to the bottom of the window

        setLocationRelativeTo(null); // Center the window on the screen
        setVisible(true); // Make the window visible
    }

    /**
     * Creates a modern-looking button with the specified text, action listener, and background color.
     * 
     * @param text The button text.
     * @param action The action listener to handle the button click event.
     * @param color The background color of the button.
     * @return A JButton with the specified properties.
     */
    private JButton createModernButton(String text, java.awt.event.ActionListener action, Color color) {
        JButton button = new JButton(text);
        button.setFont(new Font("Verdana", Font.BOLD, 14)); // Set bold font for the button text
        button.setBackground(color); // Set the background color
        button.setForeground(Color.WHITE); // Set the text color to white
        button.setFocusPainted(false); // Remove focus painting (default blue outline)
        button.setBorder(new LineBorder(color.darker(), 1, true)); // Add a border with a darker shade of the button color
        button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)); // Change the cursor to a hand when hovering over the button
        button.setOpaque(true); // Make the button opaque
        button.setPreferredSize(new Dimension(160, 40)); // Set the preferred size of the button
        button.addActionListener(action); // Add the action listener to handle button clicks
        return button;
    }

    /**
     * Handles deposit and withdrawal transactions by communicating with the server.
     * Encrypts the transaction details and verifies the server's response using MAC.
     * 
     * @param type The type of transaction ("deposit" or "withdraw").
     */
    private void transactionHandler(String type) {
        String amountStr = JOptionPane.showInputDialog(this, "Enter amount:"); // Show input dialog for the amount
        if (amountStr == null || amountStr.trim().isEmpty()) return; // Cancel if input is empty

        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                try {
                    double amount = Double.parseDouble(amountStr); // Parse the amount entered by the user
                    if (amount <= 0) { // Check if the amount is valid (positive number)
                        SwingUtilities.invokeLater(() -> infoPanel.setText("Amount must be positive."));
                        return null;
                    }

                    String query = type + ":" + amount; // Prepare the transaction query
                    String encryptQuery = MessageEncryption.encryptAES(query, encryptKey); // Encrypt the query using AES
                    String mac = MessageEncryption.generateMac(query, macKey); // Generate MAC for the query

                    // Send encrypted query and MAC to the server
                    client.getOutput().println(encryptQuery);
                    client.getOutput().println(mac);

                    // Receive the server's response
                    String encryptReply = client.getInput().readLine();
                    String macReply = client.getInput().readLine();

                    if (encryptReply == null || macReply == null) { // Handle connection loss
                        SwingUtilities.invokeLater(() -> infoPanel.setText("Connection lost. Please log in again."));
                        return null;
                    }

                    String response = MessageEncryption.decryptAES(encryptReply, encryptKey); // Decrypt the server's response
                    if (!MessageEncryption.verifyMac(response, macReply, macKey)) { // Verify the integrity of the response
                        SwingUtilities.invokeLater(() -> infoPanel.setText("Security verification failed. Try again."));
                        return null;
                    }

                    SwingUtilities.invokeLater(() -> infoPanel.setText(response)); // Display the response
                } catch (NumberFormatException e) { // Handle invalid amount format
                    SwingUtilities.invokeLater(() -> infoPanel.setText("Invalid amount format. Please enter a number."));
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> infoPanel.setText("Transaction failed: " + e.getMessage())); // Handle other exceptions
                    e.printStackTrace();
                }
                return null;
            }
        }.execute();
    }

    /**
     * Checks the user's account balance by sending a request to the server.
     * 
     * This method sends an encrypted request for the balance and verifies the server's response using MAC.
     */
    private void balanceUserCheck() {
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                try {
                    String query = "balance"; // Request for balance
                    String encryptQuery = MessageEncryption.encryptAES(query, encryptKey); // Encrypt the query using AES
                    String mac = MessageEncryption.generateMac(query, macKey); // Generate MAC for the query

                    // Send encrypted query and MAC to the server
                    client.getOutput().println(encryptQuery);
                    client.getOutput().println(mac);

                    // Receive the server's response
                    String encryptReply = client.getInput().readLine();
                    String macReply = client.getInput().readLine();

                    if (encryptReply == null || macReply == null) { // Handle connection loss
                        SwingUtilities.invokeLater(() -> infoPanel.setText("Connection lost. Please log in again."));
                        return null;
                    }

                    String reply = MessageEncryption.decryptAES(encryptReply, encryptKey); // Decrypt the server's response
                    if (!MessageEncryption.verifyMac(reply, macReply, macKey)) { // Verify the integrity of the response
                        SwingUtilities.invokeLater(() -> infoPanel.setText("Security verification failed. Try again."));
                        return null;
                    }

                    SwingUtilities.invokeLater(() -> infoPanel.setText(reply)); // Display the balance response
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> infoPanel.setText("Error checking balance: " + e.getMessage()));
                    e.printStackTrace();
                }
                return null;
            }
        }.execute();
    }

    /**
     * Logs the user out by sending an "exit" command to the server.
     * After logging out, the user is shown a message and the application is disposed.
     */
    private void logout() {
        try {
            String query = "exit"; // Request to log out
            String encryptQuery = MessageEncryption.encryptAES(query, encryptKey); // Encrypt the logout query
            String mac = MessageEncryption.generateMac(query, macKey); // Generate MAC for the query

            client.getOutput().println(encryptQuery); // Send encrypted logout request to the server
            client.getOutput().println(mac); // Send MAC to verify the integrity of the request
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            JOptionPane.showMessageDialog(this, "Logged out successfully."); // Show logout message
            dispose(); // Close the window
            new Client(); // Create a new Client object (likely to restart the application)
        }
    }
}
