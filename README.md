# Secure-Banking-System
A Java-based Secure Banking System developed to simulate a real-world ATM–Bank interaction and focuses on implementing strong security protocols alongside core banking functionalities.


<p align="left"> <b>📌 Project Overview</b> </p>
The Secure Banking System consists of a Bank Server and multiple ATM Client Machines. It replicates common banking operations while prioritizing confidentiality, authentication, and data integrity. Some core features include:

- User Account Management: Register, login, and delete accounts
- Banking Operations: Deposit, withdraw, and check account balance
- Security Enhancements:
    - Authenticated key distribution protocol
    - AES-128 encryption for transactions
    - MAC verification for integrity
    - Hashed password validation
    - Encrypted and plaintext audit logging


 
<p align="left"> <b>⚙️ System Architecture</b> </p>
The project is divided into two main layers:


1. Backend Logic: Handles authentication, encryption, account management, and secure communication.

    - Client.java – Entry point for user authentication and connection handling
    - ClientHelperFunc.java – Encrypted user requests with MAC verification
    - AuditLog.java – Logs transactions in plaintext and encrypted formats
    - MessageEncryption.java & KeyAdministrator.java – Encryption, decryption, and key management

2. Graphical User Interface (GUI): Built with Java Swing, the GUI simulates an ATM interface:

    - Login screen for existing customers
    - Registration screen for new accounts with username, password, and initial deposit
    - Dashboard for deposits, withdrawals, and balance checks
    - Account deletion screen with secure confirmation


<p align="left"> <b>🚀 How It Works</b> </p>

1. Launch the Bank Server

2. Run the ATM Client to connect

3. Register as a new user or log in with existing credentials

4. Perform transactions securely with AES-encrypted communication

5. All activities are logged in plaintext and encrypted files for auditing
