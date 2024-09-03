# Encryption-Decryption
File Encryption/Decryption with Password in .NET 7
This project demonstrates how to encrypt and decrypt files using a password in .NET 7. The application allows users to securely encrypt files and then decrypt them using the same password. It employs the AES (Advanced Encryption Standard) algorithm along with a salt and a password-based key derivation function to enhance security.

Features
Password-Based Encryption: Utilizes a user-provided password to derive encryption keys, ensuring that only individuals with the correct password can decrypt the files.
AES Encryption: Implements the industry-standard AES algorithm for robust and secure encryption.
Salt Generation: Generates a unique salt for each encryption to protect against dictionary attacks and ensure the uniqueness of encrypted files.
File Handling: Supports the encryption of any file type and retains the file's original format upon decryption.
Requirements
.NET 7 SDK: Make sure you have .NET 7 SDK installed. You can download it from the .NET official site.
IDE/Text Editor: You can use Visual Studio, Visual Studio Code, or any other code editor of your choice.

