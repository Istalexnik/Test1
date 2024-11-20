using System.Security.Cryptography;
using System.Text;

namespace WebApiHubTest1.Services
{
    public class Encryption
    {
        private readonly string encryptionKey;

        public Encryption(IConfiguration configuration)
        {
            encryptionKey = configuration["EncryptionSettings:EncryptionKey"]
            ?? throw new InvalidOperationException("Encryption key not found in environment variables.");
        }

        public string EncryptIt(string text)
        {
            return Encrypt(text);
        }

        public string DecryptIt(string text)
        {
            return Decrypt(text);
        }

        private string Encrypt(string text)
        {
            byte[] clearBytes = Encoding.Unicode.GetBytes(text);
            using (Aes aes = Aes.Create())
            {
                var rfc = new Rfc2898DeriveBytes(
                    encryptionKey,
                    new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 },
                    100_000,
                    HashAlgorithmName.SHA256
                );

                aes.Key = rfc.GetBytes(32);
                aes.IV = rfc.GetBytes(16);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        private string Decrypt(string text)
        {
            text = text.Replace(" ", "+"); // Ensure valid base64 format
            byte[] cipherBytes = Convert.FromBase64String(text);

            using (Aes aes = Aes.Create())
            {
                var rfc = new Rfc2898DeriveBytes(
                    encryptionKey,
                    new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 },
                    100_000,
                    HashAlgorithmName.SHA256
                );

                aes.Key = rfc.GetBytes(32);
                aes.IV = rfc.GetBytes(16);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                    }
                    return Encoding.Unicode.GetString(ms.ToArray());
                }
            }
        }
    }
}
