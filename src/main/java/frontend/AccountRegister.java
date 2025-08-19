package frontend;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;

/**
 * AccountRegister is a GUI window for users to register a new account.
 * It provides an interface where users can input their username, password,
 * confirm password, and initial deposit before sending the registration request.
 * It interacts with the server to register the user's account and provides feedback.
 * 
 * @author lalit
 */
public class AccountRegister extends JFrame {
    private JTextField username, deposit; // Fields for username and initial deposit
    private JPasswordField password, confirmPassword; // Fields for password and confirm password
    private JTextArea infoPanel; // Text area to display information and messages
    private Client client; // Client object for communication with the server

    /**
     * Constructor to initialize the AccountRegister window.
     * It sets up the UI components like labels, text fields, buttons, and the info panel.
     * 
     * @param client The client object used to interact with the server.
     */
    public AccountRegister(Client client) {
        this.client = client;
        setTitle("Register New Account"); // Set window title
        setSize(460, 350); // Set window size
        setLayout(new BorderLayout()); // Set layout manager to BorderLayout
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE); // Dispose the window when closed
        getContentPane().setBackground(new Color(40, 40, 40)); // Dark background color

        // Panel containing form components for username, password, confirm password, and deposit
        JPanel formPanel = new JPanel(new GridLayout(5, 2, 15, 15)); // Grid layout for form fields
        formPanel.setBackground(new Color(40, 40, 40)); // Dark background for the form
        formPanel.setBorder(new EmptyBorder(30, 40, 20, 40)); // Add padding around the form

        // Define fonts for the labels and input fields
        Font labelFont = new Font("Verdana", Font.PLAIN, 14);
        Font inputFont = new Font("Verdana", Font.PLAIN, 13);

        // Username label and text field setup
        JLabel userLabel = new JLabel("Username:");
        userLabel.setFont(labelFont);
        userLabel.setForeground(Color.WHITE); // White text for the label
        username = new JTextField();
        username.setFont(inputFont);
        username.setBorder(new LineBorder(new Color(100, 100, 100), 1, true)); // Border around username field
        username.setBackground(new Color(60, 60, 60)); // Dark background for the field
        username.setForeground(Color.WHITE); // White text for the username field

        // Password label and field setup
        JLabel passLabel = new JLabel("Password:");
        passLabel.setFont(labelFont);
        passLabel.setForeground(Color.WHITE); // White text for the label
        password = new JPasswordField();
        password.setFont(inputFont);
        password.setBorder(new LineBorder(new Color(100, 100, 100), 1, true)); // Border around password field
        password.setBackground(new Color(60, 60, 60)); // Dark background for the field
        password.setForeground(Color.WHITE); // White text for the password field

        // Confirm Password label and field setup
        JLabel confirmLabel = new JLabel("Confirm Password:");
        confirmLabel.setFont(labelFont);
        confirmLabel.setForeground(Color.WHITE); // White text for the label
        confirmPassword = new JPasswordField();
        confirmPassword.setFont(inputFont);
        confirmPassword.setBorder(new LineBorder(new Color(100, 100, 100), 1, true)); // Border around confirm password field
        confirmPassword.setBackground(new Color(60, 60, 60)); // Dark background for the field
        confirmPassword.setForeground(Color.WHITE); // White text for the confirm password field

        // Initial Deposit label and text field setup
        JLabel depositLabel = new JLabel("Initial Deposit:");
        depositLabel.setFont(labelFont);
        depositLabel.setForeground(Color.WHITE); // White text for the label
        deposit = new JTextField();
        deposit.setFont(inputFont);
        deposit.setBorder(new LineBorder(new Color(100, 100, 100), 1, true)); // Border around deposit field
        deposit.setBackground(new Color(60, 60, 60)); // Dark background for the field
        deposit.setForeground(Color.WHITE); // White text for the deposit field

        // Create and add Register button with action listener
        JButton registerButton = createStyledButton("Register", new Color(46, 204, 113)); // Green color for register button
        registerButton.addActionListener(e -> registerUser()); // Call registerUser() method on click

        // Create and add Back to Login button with action listener
        JButton backButton = createStyledButton("Back to Login", new Color(52, 152, 219)); // Blue color for back button
        backButton.addActionListener(e -> dispose()); // Dispose the window on click

        // Add form components to the panel
        formPanel.add(userLabel);
        formPanel.add(username);
        formPanel.add(passLabel);
        formPanel.add(password);
        formPanel.add(confirmLabel);
        formPanel.add(confirmPassword);
        formPanel.add(depositLabel);
        formPanel.add(deposit);
        formPanel.add(registerButton);
        formPanel.add(backButton);

        // Add form panel to the center of the window
        add(formPanel, BorderLayout.CENTER);

        // Set up the info panel to display messages like error or success messages
        infoPanel = new JTextArea(2, 30); // A text area with 2 rows and 30 columns
        infoPanel.setEditable(false); // Make the info panel non-editable
        infoPanel.setFont(new Font("Verdana", Font.PLAIN, 13));
        infoPanel.setLineWrap(true); // Wrap text within the text area
        infoPanel.setWrapStyleWord(true); // Wrap at word boundaries
        infoPanel.setBackground(new Color(60, 60, 60)); // Dark background
        infoPanel.setForeground(Color.WHITE); // White text color
        infoPanel.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(new Color(100, 100, 100), 1, true), // Border around the text area
                new EmptyBorder(10, 10, 10, 10) // Padding inside the text area
        ));

        // Add a scroll pane to the info panel for scrolling
        JScrollPane scrollPane = new JScrollPane(infoPanel);
        scrollPane.setBorder(new EmptyBorder(10, 30, 20, 30)); // Add padding around the scroll pane
        add(scrollPane, BorderLayout.SOUTH); // Add the scroll pane to the bottom of the window

        setLocationRelativeTo(null); // Center the window on the screen
        setVisible(true); // Make the window visible
    }

    /**
     * Creates a styled button with specific text and background color.
     * 
     * @param text The text to display on the button.
     * @param bgColor The background color of the button.
     * @return A styled JButton.
     */
    private JButton createStyledButton(String text, Color bgColor) {
        JButton button = new JButton(text);
        button.setFont(new Font("Verdana", Font.BOLD, 13)); // Set the font of the button
        button.setBackground(bgColor); // Set the background color
        button.setForeground(Color.WHITE); // Set the text color to white
        button.setFocusPainted(false); // Remove focus painting
        button.setBorder(new LineBorder(bgColor.darker(), 1, true)); // Set a darker border color
        button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)); // Set cursor to hand on hover
        button.setOpaque(true); // Make the button opaque
        return button;
    }

    /**
     * Handles the registration of a new user by sending the registration request to the server.
     * It verifies that the username, password, confirm password, and initial deposit are valid.
     * 
     * @throws IOException if there is an error in communication with the server.
     */
    private void registerUser() {
        String usernameText = username.getText(); // Get the username entered by the user
        String passwordText = new String(password.getPassword()); // Get the password entered by the user
        String confirmPasswordText = new String(confirmPassword.getPassword()); // Get the confirm password entered by the user
        String depositText = deposit.getText(); // Get the initial deposit entered by the user

        // Validate that all fields are filled
        if (usernameText.isEmpty() || passwordText.isEmpty() || depositText.isEmpty()) {
            infoPanel.setText("All fields must be filled."); // Show error if any field is empty
            return;
        }

        // Check if the passwords match
        if (!passwordText.equals(confirmPasswordText)) {
            infoPanel.setText("Passwords do not match. Try again."); // Show error if passwords don't match
            return;
        }

        try {
            // Send the registration request to the server
            client.getOutput().println("2"); // Command to register new account
            client.getOutput().println(usernameText); // Send the username
            client.getOutput().println(passwordText); // Send the password
            client.getOutput().println(depositText); // Send the initial deposit

            // Read the server's response
            String response = client.getInput().readLine();
            infoPanel.setText(response); // Display the server's response
        } catch (IOException e) {
            infoPanel.setText("Error communicating with server."); // Show error if communication fails
            e.printStackTrace(); // Print the exception details
        }
    }
}
