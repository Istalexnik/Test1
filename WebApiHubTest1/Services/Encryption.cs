using System.Security.Cryptography;
using System.Text;

namespace WebApiHubTest1.Services;
    public class Encryption
    {
        private readonly string encryptionKey;

        public Encryption(IConfiguration configuration)
        {
            encryptionKey = configuration["EncryptionSettings:EncryptionKey"]
                ?? throw new InvalidOperationException("Encryption key not found in configuration.");
        }

        public string Encrypt(string plaintext)
        {
            using Aes aes = Aes.Create();

            // Generate a random salt
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(salt);

            // Derive key and IV
            var rfc = new Rfc2898DeriveBytes(encryptionKey, salt, 100_000, HashAlgorithmName.SHA256);
            aes.Key = rfc.GetBytes(32);
            aes.GenerateIV(); // Random IV

            using MemoryStream ms = new();
            // Write salt and IV to the output stream
            ms.Write(salt, 0, salt.Length);
            ms.Write(aes.IV, 0, aes.IV.Length);

            using CryptoStream cs = new(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            cs.Write(plaintextBytes, 0, plaintextBytes.Length);
            cs.FlushFinalBlock();

            return Convert.ToBase64String(ms.ToArray());
        }

        public string Decrypt(string ciphertext)
        {
            byte[] cipherBytes = Convert.FromBase64String(ciphertext);

            using MemoryStream ms = new(cipherBytes);

            // Read salt
            byte[] salt = new byte[16];
            ms.Read(salt, 0, salt.Length);

            // Read IV
            byte[] iv = new byte[16];
            ms.Read(iv, 0, iv.Length);

            using Aes aes = Aes.Create();

            // Derive key and IV
            var rfc = new Rfc2898DeriveBytes(encryptionKey, salt, 100_000, HashAlgorithmName.SHA256);
            aes.Key = rfc.GetBytes(32);
            aes.IV = iv;

            using CryptoStream cs = new(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using MemoryStream output = new();
            cs.CopyTo(output);

            return Encoding.UTF8.GetString(output.ToArray());
        }
    }
