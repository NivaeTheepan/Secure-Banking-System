package frontend;


import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;

/**
 * AccountDelete is a GUI window for users to delete their accounts.
 * It provides an interface where users can input their username, password,
 * and confirm password before confirming the deletion of their account.
 * It interacts with the server to delete the user's account and provides feedback.
 * 
 * @author lalit
 */
public class AccountDelete extends JFrame {
    private JTextField username; // Field for the username input
    private JPasswordField password, confirmPassword; // Fields for password and confirm password
    private JTextArea infoPanel; // Text area to display information and messages
    private Client client; // Client object for communication with the server

    /**
     * Constructor to initialize the AccountDelete window.
     * It sets up the UI components like labels, text fields, buttons, and the info panel.
     * 
     * @param client The client object used to interact with the server.
     */
    public AccountDelete(Client client) {
        this.client = client;
        setTitle("Delete Account"); // Set window title
        setSize(460, 320); // Set window size
        setLayout(new BorderLayout()); // Set layout manager to BorderLayout
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE); // Dispose the window when closed
        getContentPane().setBackground(new Color(45, 45, 45)); // Dark background color

        // Panel containing form components for username, password, and confirm password
        JPanel formPanel = new JPanel(new GridLayout(4, 2, 15, 15)); // Grid layout for form fields
        formPanel.setBackground(new Color(45, 45, 45)); // Dark background for the form
        formPanel.setBorder(new EmptyBorder(30, 40, 20, 40)); // Add padding around the form

        // Define fonts and colors for the labels and input fields
        Font labelFont = new Font("Verdana", Font.PLAIN, 14);
        Font inputFont = new Font("Verdana", Font.PLAIN, 13);
        Color labelColor = new Color(220, 220, 220);
        Color inputBg = new Color(60, 60, 60);
        Color inputFg = new Color(230, 230, 230);
        Color borderColor = new Color(100, 100, 100);

        // Username label and text field setup
        JLabel userLabel = new JLabel("Username:");
        userLabel.setFont(labelFont);
        userLabel.setForeground(labelColor);
        username = new JTextField();
        username.setFont(inputFont);
        username.setBackground(inputBg);
        username.setForeground(inputFg);
        username.setCaretColor(inputFg);
        username.setBorder(new LineBorder(borderColor, 1, true)); // Border around input field

        // Password label and field setup
        JLabel passLabel = new JLabel("Password:");
        passLabel.setFont(labelFont);
        passLabel.setForeground(labelColor);
        password = new JPasswordField();
        password.setFont(inputFont);
        password.setBackground(inputBg);
        password.setForeground(inputFg);
        password.setCaretColor(inputFg);
        password.setBorder(new LineBorder(borderColor, 1, true)); // Border around password field

        // Confirm Password label and field setup
        JLabel confirmLabel = new JLabel("Confirm Password:");
        confirmLabel.setFont(labelFont);
        confirmLabel.setForeground(labelColor);
        confirmPassword = new JPasswordField();
        confirmPassword.setFont(inputFont);
        confirmPassword.setBackground(inputBg);
        confirmPassword.setForeground(inputFg);
        confirmPassword.setCaretColor(inputFg);
        confirmPassword.setBorder(new LineBorder(borderColor, 1, true)); // Border around confirm password field

        // Create and add Delete Account button with action listener
        JButton deleteButton = createStyledButton("Delete Account", new Color(192, 57, 43));
        deleteButton.addActionListener(e -> confirmDelete()); // Call confirmDelete() method on click

        // Create and add Back to Login button with action listener
        JButton backButton = createStyledButton("Back to Login", new Color(41, 128, 185));
        backButton.addActionListener(e -> dispose()); // Dispose the window on click

        // Add the components to the form panel
        formPanel.add(userLabel);
        formPanel.add(username);
        formPanel.add(passLabel);
        formPanel.add(password);
        formPanel.add(confirmLabel);
        formPanel.add(confirmPassword);
        formPanel.add(deleteButton);
        formPanel.add(backButton);

        // Add form panel to the center of the window
        add(formPanel, BorderLayout.CENTER);

        // Set up the info panel to display messages like error or success messages
        infoPanel = new JTextArea(3, 30); // A text area with 3 rows and 30 columns
        infoPanel.setEditable(false); // Make the info panel non-editable
        infoPanel.setFont(inputFont);
        infoPanel.setLineWrap(true); // Wrap text within the text area
        infoPanel.setWrapStyleWord(true); // Wrap at word boundaries
        infoPanel.setBackground(new Color(60, 60, 60)); // Dark background
        infoPanel.setForeground(new Color(230, 230, 230)); // Light text color
        infoPanel.setCaretColor(new Color(230, 230, 230)); // Set caret color
        infoPanel.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(borderColor, 1, true), // Border around the text area
                new EmptyBorder(10, 10, 10, 10) // Padding inside the text area
        ));

        // Add a scroll pane to the info panel for scrolling
        JScrollPane scrollPane = new JScrollPane(infoPanel);
        scrollPane.getViewport().setBackground(new Color(60, 60, 60)); // Set background color of the scroll pane
        scrollPane.setBorder(new EmptyBorder(10, 30, 20, 30)); // Set padding around the scroll pane
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
     * Prompts the user to confirm the deletion of their account.
     * If confirmed, it calls the deleteUser() method to proceed.
     */
    private void confirmDelete() {
        // Show a confirmation dialog to the user
        int confirm = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to delete your account? This cannot be undone.",
                "Confirm Deletion", JOptionPane.YES_NO_OPTION);

        // If user confirms, proceed with account deletion
        if (confirm == JOptionPane.YES_OPTION) {
            deleteUser(); // Call deleteUser() method
        }
    }

    /**
     * Handles the deletion of the user's account by sending the request to the server.
     * It verifies that the username and password are valid and matches the confirmation.
     * 
     * @throws IOException if there is an error in communication with the server.
     */
    private void deleteUser() {
        String usernameText = username.getText(); // Get the username entered by the user
        String passwordText = new String(password.getPassword()); // Get the password entered by the user
        String confirmPasswordText = new String(confirmPassword.getPassword()); // Get the confirm password entered by the user

        // Validate that username and password are not empty
        if (usernameText.isEmpty() || passwordText.isEmpty()) {
            infoPanel.setText("Username and password cannot be empty."); // Show error if fields are empty
            return;
        }

        // Check if the passwords match
        if (!passwordText.equals(confirmPasswordText)) {
            infoPanel.setText("Passwords do not match. Try again."); // Show error if passwords don't match
            return;
        }

        try {
            // Send the deletion request to the server
            client.getOutput().println("3"); // Command to delete account
            client.getOutput().println(usernameText); // Send the username
            client.getOutput().println(passwordText); // Send the password

            // Read the server's response
            String response = client.getInput().readLine();
            infoPanel.setText(response); // Display the server's response
        } catch (IOException e) {
            infoPanel.setText("Error communicating with server."); // Show error if communication fails
            e.printStackTrace(); // Print the stack trace for debugging
        }
    }
}
