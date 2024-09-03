using System.Security.Cryptography;
using System.Text;

namespace EncriptionDecription.Generic
{
    public class Static
    {
        private const int SaltSize = 16; // Salt size in bytes
        private const int KeySize = 32; // Key size in bytes
        private const int Iterations = 10000; // Iterations for key derivation
        public static void EncryptFile(IFormFile inputFile, string outputPath, string password)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = GenerateKey(password);
                aesAlg.IV = aesAlg.Key.Take(16).ToArray(); // Use the first 16 bytes of the key as IV

                using (FileStream outputStream = File.Create(outputPath))
                using (CryptoStream cryptoStream = new CryptoStream(outputStream, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
                using (Stream inputStream = inputFile.OpenReadStream())
                {
                    inputStream.CopyTo(cryptoStream);
                }
            }
        }
        public static void DecryptFile(string inputPath, string outputPath, string password)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = GenerateKey(password);
                aesAlg.IV = aesAlg.Key.Take(16).ToArray(); // Use the first 16 bytes of the key as IV

                using (FileStream inputStream = File.OpenRead(inputPath))
                using (CryptoStream cryptoStream = new CryptoStream(inputStream, aesAlg.CreateDecryptor(), CryptoStreamMode.Read))
                using (FileStream outputStream = File.Create(outputPath))
                {
                    cryptoStream.CopyTo(outputStream);
                }
            }
        }


        private static byte[] GenerateKey(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }
        public static byte[] EncryptFileBytes(byte[] fileBytes, string password)
        {
            byte[] encryptedBytes;

            using (Aes aesAlg = Aes.Create())
            {
                byte[] key = new Rfc2898DeriveBytes(password, new byte[] { 0x49, 0x76, 0x61, 0x6E, 0x65, 0x54, 0x6F, 0x4D, 0x79, 0x4B, 0x65, 0x79, 0x36 }, 1000).GetBytes(32);
                byte[] iv = new Rfc2898DeriveBytes(password, new byte[] { 0x49, 0x76, 0x61, 0x6E, 0x65, 0x54, 0x6F, 0x4D, 0x79, 0x4B, 0x65, 0x79, 0x36 }, 1000).GetBytes(16);

                aesAlg.Key = key;
                aesAlg.IV = iv;

                aesAlg.Padding = PaddingMode.PKCS7; // Set the padding mode

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            csEncrypt.Write(fileBytes, 0, fileBytes.Length);
                            csEncrypt.FlushFinalBlock();
                        }
                    }
                    encryptedBytes = msEncrypt.ToArray();
                }
            }

            return encryptedBytes;
        }

        public static byte[] DecryptFileBytes(byte[] fileBytes, string password)
        {
            byte[] decryptedBytes;

            using (Aes aesAlg = Aes.Create())
            {
                byte[] key = new Rfc2898DeriveBytes(password, new byte[] { 0x49, 0x76, 0x61, 0x6E, 0x65, 0x54, 0x6F, 0x4D, 0x79, 0x4B, 0x65, 0x79, 0x36 }, 1000).GetBytes(32);
                byte[] iv = new Rfc2898DeriveBytes(password, new byte[] { 0x49, 0x76, 0x61, 0x6E, 0x65, 0x54, 0x6F, 0x4D, 0x79, 0x4B, 0x65, 0x79, 0x36 }, 1000).GetBytes(16);

                aesAlg.Key = key;
                aesAlg.IV = iv;

                aesAlg.Padding = PaddingMode.PKCS7; // Set the padding mode

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(fileBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (MemoryStream ms = new MemoryStream())
                        {
                            csDecrypt.CopyTo(ms);
                            decryptedBytes = ms.ToArray();
                        }
                    }
                }
            }

            return decryptedBytes;
        }
        private static byte[] GenerateKeyFromPassword(string password, int keySize)
        {
            const int iterations = 10000; // Adjust this value based on your security needs
            byte[] salt = Encoding.UTF8.GetBytes("121232114115"); // Change this to your salt value

            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations))
            {
                return pbkdf2.GetBytes(keySize / 8); // Divide by 8 to get bytes
            }
        }
        public static string EncryptString(string plainText, string password)
        {
            byte[] encryptedBytes;

            using (Aes aesAlg = Aes.Create())
            {
                Rfc2898DeriveBytes keyDerivationFunction = new Rfc2898DeriveBytes(password, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });

                aesAlg.Key = keyDerivationFunction.GetBytes(32); // AES-256 key
                aesAlg.IV = keyDerivationFunction.GetBytes(16); // AES-128 IV

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encryptedBytes = msEncrypt.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(encryptedBytes);
        }
        public static string DecryptString(string cipherText, string password)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

            using (Aes aesAlg = Aes.Create())
            {
                Rfc2898DeriveBytes keyDerivationFunction = new Rfc2898DeriveBytes(password, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });

                aesAlg.Key = keyDerivationFunction.GetBytes(32); // AES-256 key
                aesAlg.IV = keyDerivationFunction.GetBytes(16); // AES-128 IV

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherTextBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        private static byte[] GenerateRandomSalt()
        {
            byte[] salt = new byte[SaltSize];
            using RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(salt);
            return salt;
        }

        private static byte[] GenerateKey(string password, byte[] salt)
        {
            using Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations);
            return pbkdf2.GetBytes(KeySize);
        }
    }
}
