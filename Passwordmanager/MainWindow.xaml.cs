using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Collections.Generic;
using Microsoft.Data.Sqlite;
using System.Windows.Controls;
using System.Windows;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Windows.Media.Imaging;
using System.Reflection;
using System.Data.SQLite;

namespace Passwordmanager
{
    public class PasswordEntry
    {
        public int Id { get; set; }
        public string ServiceName { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public partial class MainWindow : Window
    {
        private string storedMasterPasswordHash = "";
        private byte[] encryptionKey = Array.Empty<byte>();

        public MainWindow()
        {
            InitializeComponent();
            InitializeDatabase();
            RetrieveMasterPasswordHashFromDatabase();

            if (string.IsNullOrEmpty(storedMasterPasswordHash))
            {
                PromptSetMasterPassword();
            }
            else
            {
                popupMasterPassword.IsOpen = true;
            }
        }

        private void InitializeDatabase()
        {
            try
            {
                // Construct the data folder and file path
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string databaseFullPath = Path.Combine(dataFolderPath, "passwords.db");

                // Check for database folder
                if (!Directory.Exists(dataFolderPath))
                {
                    Directory.CreateDirectory(dataFolderPath);
                }

                // Connect to the database
                using (SQLiteConnection connection = new SQLiteConnection($"Data Source={databaseFullPath}"))
                {
                    connection.Open();

                    // Create Database tables
                    using (SQLiteCommand command = new SQLiteCommand(connection))
                    {
                        command.CommandText = @"CREATE TABLE IF NOT EXISTS Passwords (
                                            Id INTEGER PRIMARY KEY,
                                            ServiceName TEXT,
                                            Username TEXT,
                                            Password TEXT
                                        );";
                        command.ExecuteNonQuery();
                    }

                    using (SQLiteCommand command = new SQLiteCommand(connection))
                    {
                        command.CommandText = @"CREATE TABLE IF NOT EXISTS MasterPassword (
                                            Id INTEGER PRIMARY KEY,
                                            PasswordHash TEXT
                                        );";
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error initializing database: {ex.Message}");
            }
        }


        private void RetrieveMasterPasswordHashFromDatabase()
        {
            try
            {
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string databaseFullPath = Path.Combine(dataFolderPath, "passwords.db");

                using (var connection = new SqliteConnection($"Data Source={databaseFullPath}"))
                {
                    connection.Open();

                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT PasswordHash FROM MasterPassword";
                        var result = command.ExecuteScalar();
                        if (result != null)
                        {
                            storedMasterPasswordHash = result.ToString();
                            InitializeEncryptionKey(storedMasterPasswordHash);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error retrieving master password hash from database: {ex.Message}");
            }
        }

        private void PromptSetMasterPassword()
        {
            popupSetMasterPassword.IsOpen = true;
        }

        private void SetMasterPassword(string masterPassword)
        {
            try
            {
                string passwordHash = BCrypt.Net.BCrypt.HashPassword(masterPassword, BCrypt.Net.BCrypt.GenerateSalt());
                storedMasterPasswordHash = passwordHash;
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string databaseFullPath = Path.Combine(dataFolderPath, "passwords.db");
                using (var connection = new SqliteConnection($"Data Source={databaseFullPath}"))
                {
                    connection.Open();

                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "INSERT INTO MasterPassword (PasswordHash) VALUES (@PasswordHash)";
                        command.Parameters.AddWithValue("@PasswordHash", passwordHash);
                        command.ExecuteNonQuery();
                    }
                }

                InitializeEncryptionKey(storedMasterPasswordHash);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error setting master password: {ex.Message}");
            }
        }

        // Initializes the encryption key used for encrypting and decrypting strings.
        private void InitializeEncryptionKey(string masterPasswordHash)
        {
            if (!string.IsNullOrEmpty(masterPasswordHash))
            {
                // Convert the master password hash to bytes and resize to 32 bytes
                byte[] keyBytes = Encoding.UTF8.GetBytes(masterPasswordHash);
                Array.Resize(ref keyBytes, 32);
                encryptionKey = keyBytes;
            }
            else
            {
                MessageBox.Show("Master password hash is empty or null.");
            }
        }

        // Encrypts a plain text string using AES encryption.
        private string EncryptString(string plainText)
        {
            if (encryptionKey != null && encryptionKey.Length > 0)
            {
                using (var aesAlg = Aes.Create())
                {
                    aesAlg.Key = encryptionKey;
                    aesAlg.Mode = CipherMode.CBC;
                    aesAlg.GenerateIV();

                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        // Write IV length and IV to the memory stream
                        msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                        msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);

                        // Encrypt the plain text and write it to the memory stream
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }

                        // Convert the encrypted data to Base64 string
                        return Convert.ToBase64String(msEncrypt.ToArray());
                    }
                }
            }
            else
            {
                MessageBox.Show("Encryption key is not initialized.");
                return string.Empty;
            }
        }

        // Decrypts a cipher text string using AES decryption.
        private string DecryptString(string cipherText)
        {
            if (encryptionKey != null && encryptionKey.Length > 0)
            {
                byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

                using (var aesAlg = Aes.Create())
                {
                    aesAlg.Key = encryptionKey;
                    aesAlg.Mode = CipherMode.CBC;

                    // Extract IV length and IV from the cipher text bytes
                    int ivLength = BitConverter.ToInt32(cipherTextBytes, 0);
                    aesAlg.IV = cipherTextBytes.Skip(sizeof(int)).Take(ivLength).ToArray();

                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                    using (MemoryStream msDecrypt = new MemoryStream(cipherTextBytes, sizeof(int) + ivLength, cipherTextBytes.Length - (sizeof(int) + ivLength)))
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        // Read the decrypted data from the stream and return as string
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
            else
            {
                MessageBox.Show("Encryption key is not initialized.");
                return string.Empty;
            }
        }

        private void BtnSubmitEnterMasterPassword_Click(object sender, RoutedEventArgs e)
        {
            string masterPassword = txtEnterMasterPassword.Password;
            if (ValidateMasterPassword(masterPassword))
            {
                DecryptAndDisplayPasswords(masterPassword);
                popupMasterPassword.IsOpen = false;

                DataGrid.Visibility = Visibility.Visible;
                DataGrid.ItemsSource = GetPasswords();
            }
            else
            {
                MessageBox.Show("Invalid master password!");
            }
        }

        private bool ValidateMasterPassword(string masterPassword)
        {
            return BCrypt.Net.BCrypt.Verify(masterPassword, storedMasterPasswordHash);
        }

        private void DecryptAndDisplayPasswords(string masterPassword)
        {
            List<PasswordEntry> decryptedPasswords = DecryptPasswords(masterPassword);
            DataGrid.ItemsSource = decryptedPasswords;
        }

        private List<PasswordEntry> DecryptPasswords(string masterPassword)
        {
            List<PasswordEntry> decryptedPasswords = new List<PasswordEntry>();

            try
            {
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string databaseFullPath = Path.Combine(dataFolderPath, "passwords.db");

                using (var connection = new SqliteConnection($"Data Source={databaseFullPath}"))
                {
                    connection.Open();

                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT * FROM Passwords";
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                PasswordEntry entry = new PasswordEntry
                                {
                                    Id = reader.GetInt32(0),
                                    ServiceName = DecryptString(reader.GetString(1)),
                                    Username = DecryptString(reader.GetString(2)),
                                    Password = DecryptString(reader.GetString(3))
                                };
                                decryptedPasswords.Add(entry);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error decrypting passwords: {ex.Message}");
            }

            return decryptedPasswords;
        }

        private void BtnSubmitSetMasterPassword_Click(object sender, RoutedEventArgs e)
        {
            string masterPassword = txtSetMasterPassword.Password;
            SetMasterPassword(masterPassword);
            popupSetMasterPassword.IsOpen = false;
            popupMasterPassword.IsOpen = true;
        }

        private void BtnAdd_Click(object sender, RoutedEventArgs e)
        {
            string service = txtService.Text;
            string username = txtUsername.Text;
            string password = txtPassword.Password;

            SavePassword(service, username, password);
            DataGrid.ItemsSource = GetPasswords();

            txtService.Clear();
            txtUsername.Clear();
            txtPassword.Clear();
        }

        private void SavePassword(string serviceName, string username, string password)
        {
            try
            {
                string encryptedServiceName = EncryptString(serviceName);
                string encryptedUsername = EncryptString(username);
                string encryptedPassword = EncryptString(password);
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string databaseFullPath = Path.Combine(dataFolderPath, "passwords.db");
                using (var connection = new SqliteConnection($"Data Source={databaseFullPath}"))
                {
                    connection.Open();

                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "INSERT INTO Passwords (ServiceName, Username, Password) VALUES (@ServiceName, @Username, @Password)";
                        command.Parameters.AddWithValue("@ServiceName", encryptedServiceName);
                        command.Parameters.AddWithValue("@Username", encryptedUsername);
                        command.Parameters.AddWithValue("@Password", encryptedPassword);
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving password: {ex.Message}");
            }
        }

        private List<PasswordEntry> GetPasswords()
        {
            List<PasswordEntry> passwords = new List<PasswordEntry>();
            try
            {
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string databaseFullPath = Path.Combine(dataFolderPath, "passwords.db");

                using (var connection = new SqliteConnection($"Data Source={databaseFullPath}"))
                {
                    connection.Open();

                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT * FROM Passwords";
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                PasswordEntry entry = new PasswordEntry
                                {
                                    Id = reader.GetInt32(0),
                                    ServiceName = DecryptString(reader.GetString(1)),
                                    Username = DecryptString(reader.GetString(2)),
                                    Password = DecryptString(reader.GetString(3))
                                };
                                passwords.Add(entry);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error retrieving passwords: {ex.Message}");
            }

            return passwords;
        }

        private void BtnDelete_Click(object sender, RoutedEventArgs e)
        {
            PasswordEntry selectedEntry = (PasswordEntry)DataGrid.SelectedItem;
            if (selectedEntry != null)
            {
                DeletePassword(selectedEntry.Id);
                DataGrid.ItemsSource = GetPasswords();
            }
        }

        private void DeletePassword(int id)
        {
            try
            {
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PasswordManager");
                string databaseFullPath = Path.Combine(dataFolderPath, "passwords.db");

                using (var connection = new SqliteConnection($"Data Source={databaseFullPath}"))
                {
                    connection.Open();

                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "DELETE FROM Passwords WHERE Id = @Id";
                        command.Parameters.AddWithValue("@Id", id);
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error deleting password: {ex.Message}");
            }
        }

        private string GeneratePassword(int length)
            {
                const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_-+=<>?";
                StringBuilder res = new StringBuilder();
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                {
                    byte[] uintBuffer = new byte[sizeof(uint)];

                    while (length-- > 0)
                    {
                        rng.GetBytes(uintBuffer);
                        uint num = BitConverter.ToUInt32(uintBuffer, 0);
                        res.Append(valid[(int)(num % (uint)valid.Length)]);
                    }
                }
                return res.ToString();
            }
        private void BtnGenerate_Click(object sender, RoutedEventArgs e)
        {
            string generatedPassword = GeneratePassword(16); 
            txtGeneratedPassword.Text = generatedPassword; 
        }


    }
}
