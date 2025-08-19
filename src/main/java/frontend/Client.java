package frontend;

import backend.KeyAdministrator;
import com.formdev.flatlaf.FlatDarkLaf;
import frontend.AccountDashboard;
import frontend.AccountDelete;
import frontend.AccountRegister;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Base64;

public class Client {
    // Constants for server address and port
    private static final String SERVER_ADDRESS = "localhost";
    private static final int PORT = 4444;
    
    // Member variables for socket, input/output streams, and UI components
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;
    private JFrame frame;
    private JTextField username;
    private JPasswordField password;
    private JTextArea infoPanel;

    public Client() {
        // Attempt to set the Look and Feel to a dark theme
        try {
            UIManager.setLookAndFeel(new FlatDarkLaf());
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Initialize the UI in the Swing event dispatch thread
        SwingUtilities.invokeLater(this::initialize);
    }

    private void initialize() {
        // Set up the main window frame
        frame = new JFrame("Secure Banking System - ATM");
        frame.setSize(480, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());

        // Set up the main panel with GridBagLayout for flexible component placement
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(30, 30, 20, 30));

        // GridBagConstraints to manage the placement of components in the panel
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(12, 12, 12, 12);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Font setup for labels and input fields
        Font labelFont = new Font("Verdana", Font.PLAIN, 14);
        Font inputFont = new Font("Verdana", Font.PLAIN, 13);

        // Username label and text field
        gbc.gridx = 0; gbc.gridy = 0;
        JLabel userLabel = new JLabel("Username:");
        userLabel.setFont(labelFont);
        panel.add(userLabel, gbc);

        gbc.gridx = 1;
        username = new JTextField(15);
        username.setFont(inputFont);
        panel.add(username, gbc);

        // Password label and password field
        gbc.gridx = 0; gbc.gridy = 1;
        JLabel passLabel = new JLabel("Password:");
        passLabel.setFont(labelFont);
        panel.add(passLabel, gbc);

        gbc.gridx = 1;
        password = new JPasswordField(15);
        password.setFont(inputFont);
        panel.add(password, gbc);

        // Register account button
        gbc.gridy = 2; gbc.gridx = 0;
        JButton registerButton = createStyledButton("Register", new Color(46, 204, 113));
        registerButton.addActionListener(e -> new AccountRegister(this)); // Open registration screen
        panel.add(registerButton, gbc);

        // Delete account button
        gbc.gridx = 1;
        JButton deleteButton = createStyledButton("Delete Account", new Color(231, 76, 60));
        deleteButton.addActionListener(e -> new AccountDelete(this)); // Open delete account screen
        panel.add(deleteButton, gbc);

        // Login button
        gbc.gridy = 3; gbc.gridx = 0;
        JButton loginButton = createStyledButton("Login", new Color(52, 152, 219));
        loginButton.addActionListener(e -> login()); // Call login method when clicked
        panel.add(loginButton, gbc);

        // Exit button to close the application
        gbc.gridx = 1;
        JButton exitButton = createStyledButton("Exit", new Color(149, 165, 166));
        exitButton.addActionListener(e -> System.exit(0)); // Exit the program
        panel.add(exitButton, gbc);

        // Add the main panel to the frame
        frame.add(panel, BorderLayout.CENTER);

        // Info panel for showing status messages
        infoPanel = new JTextArea(3, 30);
        infoPanel.setEditable(false);
        infoPanel.setFont(new Font("Verdana", Font.PLAIN, 13));
        infoPanel.setLineWrap(true);
        infoPanel.setWrapStyleWord(true);
        infoPanel.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(180, 180, 180), 1, true),
                new EmptyBorder(10, 10, 10, 10)
        ));

        // Scroll pane for the info panel
        JScrollPane scrollPane = new JScrollPane(infoPanel);
        scrollPane.setBorder(new EmptyBorder(10, 30, 20, 30));
        frame.add(scrollPane, BorderLayout.SOUTH);

        // Set the frame visible and centered on the screen
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

        // Refresh the UI to apply the LAF everywhere
        SwingUtilities.updateComponentTreeUI(frame);

        // Attempt to connect to the server
        try {
            socket = new Socket(SERVER_ADDRESS, PORT); // Connect to server
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);
            infoPanel.setText("Connected to the bank server.");
        } catch (IOException e) {
            infoPanel.setText("Error connecting to server. Please try again later.");
            e.printStackTrace();
        }
    }

    // Helper method to create a styled button
    private JButton createStyledButton(String text, Color bgColor) {
        JButton button = new JButton(text);
        button.setFont(new Font("Verdana", Font.BOLD, 13));
        button.setBackground(bgColor);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorder(new LineBorder(bgColor.darker(), 1, true));
        button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        button.setOpaque(true);
        return button;
    }

    // Method to handle the login functionality
    private void login() {
        String usernameText = username.getText().trim(); // Get the username
        String passwordText = new String(password.getPassword()).trim(); // Get the password

        // Validate that both username and password are provided
        if (usernameText.isEmpty() || passwordText.isEmpty()) {
            infoPanel.setText("Please enter both username and password.");
            return;
        }

        // Perform the login in a background thread to avoid freezing the UI
        new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() throws Exception {
                try {
                    // Send login details to the server
                    out.println("1");
                    out.println(usernameText);
                    out.println(passwordText);

                    // Get the server's response
                    String response = in.readLine();
                    if (response == null) {
                        return false;
                    }

                    // If the response contains "successful", process encryption keys
                    if (response.contains("successful")) {
                        String encKeyStr = in.readLine();
                        String macKeyStr = in.readLine();

                        // Decode the encryption and MAC keys from Base64
                        byte[] encKeyBytes = Base64.getDecoder().decode(encKeyStr);
                        byte[] macKeyBytes = Base64.getDecoder().decode(macKeyStr);

                        // Create SecretKey objects for AES and HMAC
                        SecretKey encKey = new SecretKeySpec(encKeyBytes, "AES");
                        SecretKey macKey = new SecretKeySpec(macKeyBytes, "HmacSHA256");

                        // Store the keys using a key administrator
                        KeyAdministrator.generateKeys(encKey, macKey);
                        return true;
                    }
                    return false;
                } catch (IOException e) {
                    e.printStackTrace();
                    return false;
                }
            }

            @Override
            protected void done() {
                try {
                    // After background processing, check if login was successful
                    if (get()) {
                        infoPanel.setText("Login successful! Opening dashboard...");
                        SwingUtilities.invokeLater(() -> {
                            // Open the dashboard and close the login frame
                            new AccountDashboard(Client.this, usernameText);
                            frame.dispose();
                        });
                    } else {
                        infoPanel.setText("Invalid credentials. Try again.");
                        username.setText("");
                        password.setText("");
                    }
                } catch (Exception e) {
                    infoPanel.setText("Error during login. Try again.");
                    e.printStackTrace();
                }
            }
        }.execute();
    }

    // Getter methods for output, input streams, and socket
    public PrintWriter getOutput() {
        return out;
    }

    public BufferedReader getInput() {
        return in;
    }

    public Socket getSocket() {
        return socket;
    }

    // Main method to run the client application
    public static void main(String[] args) {
        new Client();
    }
}
