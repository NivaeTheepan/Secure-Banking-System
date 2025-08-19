package frontend;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;

/**
 * Server class manages the main operations of a server, including:
 * 1. Loading user data from a database file.
 * 2. Accepting client connections.
 * 3. Handling multiple clients by spawning new threads.
 * 4. Saving updates to the database.
 * 
 * It maintains two hash maps: one for storing users and another for their account balances.
 * 
 * @author lalit
 */
public class Server {
    private static final int PORT = 4444; // Port number for the server to listen on
    private static final String DATABASE_FILE = "database.txt"; // File to store user data and balances
    private static HashMap<String, String> users = new HashMap<>(); // Stores usernames and passwords
    private static HashMap<String, Double> balances = new HashMap<>(); // Stores user balances
    
    /**
     * Main method initializes the server, loads the database, and listens for client connections.
     * For each client connection, a new thread is spawned to handle communication with the client.
     */
    public static void main(String[] args) {
        loadDatabase(); // Load user data and balances from the database file

        try (ServerSocket serverSocket = new ServerSocket(PORT)) { // Create a server socket to listen on the specified port
            System.out.println("Server is running on port " + PORT);

            while (true) { // Keep accepting incoming client connections
                Socket clientSocket = serverSocket.accept(); // Accept a new client connection
                System.out.println("Client connected: " + clientSocket.getInetAddress()); // Print client details
                new Thread(new ClientHelperFunc(clientSocket)).start(); // Create and start a new thread to handle the client
            }
        } catch (IOException e) {
            e.printStackTrace(); // Handle IOExceptions during server socket operations
        }
    }

    /**
     * Loads the user data and balances from the database file into the hash maps.
     * Each line in the file is expected to be in the format: username:password:balance
     * 
     * If the database file does not exist, an empty database will be created.
     */
    private static void loadDatabase() {
        try (BufferedReader reader = new BufferedReader(new FileReader(DATABASE_FILE))) { // Read the file line by line
            String line;
            while ((line = reader.readLine()) != null) { // Read each line in the file
                String[] parts = line.split(":"); // Split the line into username, password, and balance
                users.put(parts[0], parts[1]); // Store the username and password in the users map
                balances.put(parts[0], Double.parseDouble(parts[2])); // Store the balance in the balances map
            }
            System.out.println("Database loaded successfully."); // Confirm successful loading of the database
        } catch (IOException e) {
            System.out.println("No database found. Creating a new database."); // Handle the case when the database file doesn't exist
        }
    }

    /**
     * Saves the current state of users and balances to the database file.
     * The data is written in the format: username:password:balance
     */
    static void saveDatabase() {
        try (PrintWriter writer = new PrintWriter(new FileWriter(DATABASE_FILE))) { // Open the file for writing
            // Iterate over all users and write their information to the file
            for (String user : users.keySet()) {
                writer.println(user + ":" + users.get(user) + ":" + balances.get(user)); // Write username, password, and balance
            }
            System.out.println("Database saved successfully."); // Confirm successful saving of the database
        } catch (IOException e) {
            e.printStackTrace(); // Handle IOExceptions during database saving
        }
    }

    /**
     * Returns the map containing all users.
     * 
     * @return HashMap of users where the key is the username and the value is the password
     */
    static HashMap<String, String> getUsers() {
        return users;
    }

    /**
     * Returns the map containing all user balances.
     * 
     * @return HashMap of balances where the key is the username and the value is the balance
     */
    static HashMap<String, Double> getBalances() {
        return balances;
    }
}
