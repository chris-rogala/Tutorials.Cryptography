using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Tutorials.Cryptography.App
{
    class Program
    {
        // TODO: DO NOT DO THIS!! Store these in your certificate store
        private static Func<X509Certificate2> GetPrivateAssymetricKeyCert = () => new X509Certificate2(Convert.FromBase64String(Globals.PrivateCertData), "testing");
        public static Func<X509Certificate2> GetPublicAssymetricKeyCert = () => new X509Certificate2(Convert.FromBase64String(Globals.PublicCertData));

        static async Task Main(string[] args)
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("Hello World!");
            byte[] encryptedData = null;
            byte[] encryptedSymetricKey = null;
            byte[] encryptedSymetricIV = null;
            byte[] decryptedData = null;

            using (Aes aes = Aes.Create())
            using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            using (MemoryStream contentStream = new MemoryStream(data))
            using (MemoryStream msEncrypt = new MemoryStream())
            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                using (StreamReader reader = new StreamReader(contentStream))
                using (SHA512 sHA512 = new SHA512Managed())
                {
                    await swEncrypt.WriteAsync(await reader.ReadToEndAsync());
                }

                encryptedData = msEncrypt.ToArray();
                using (var publickey = GetPublicAssymetricKeyCert().GetRSAPublicKey())
                {
                    encryptedSymetricKey = publickey.Encrypt(aes.Key, RSAEncryptionPadding.Pkcs1);
                    encryptedSymetricIV = publickey.Encrypt(aes.IV, RSAEncryptionPadding.Pkcs1);
                }
            }

            Console.WriteLine($"Data: {System.Text.Encoding.UTF8.GetString(data)}");
            Console.WriteLine($"Encrypted Data: {System.Text.Encoding.UTF8.GetString(encryptedData)}");
            Console.WriteLine($"Certificate Public Key: {GetPublicAssymetricKeyCert().PublicKey}");
            Console.WriteLine($"Certificate Private Key: {GetPublicAssymetricKeyCert().PrivateKey}");
            Console.WriteLine($"{Environment.NewLine}***The symetric key has been disposed of, so now the content cannot be decrypted***");


            Console.WriteLine($"{Environment.NewLine}Press any key to decrypt the content using the private key...");
            Console.ReadKey();
            Console.Clear();

            using (var aes = Aes.Create())
            {
                using (RSA privateKey = GetPrivateAssymetricKeyCert().GetRSAPrivateKey())
                {
                    aes.Key = privateKey.Decrypt(encryptedSymetricKey, RSAEncryptionPadding.Pkcs1);
                    aes.IV = privateKey.Decrypt(encryptedSymetricIV, RSAEncryptionPadding.Pkcs1);
                }

                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (MemoryStream msDecrypt = new MemoryStream(encryptedData))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (MemoryStream memoryStream = new MemoryStream())
                using (SHA512 sHA512 = new SHA512Managed())
                {
                    await csDecrypt.CopyToAsync(memoryStream);
                    decryptedData = memoryStream.ToArray();
                }
            }

            Console.WriteLine($"Decrypted Data: {System.Text.Encoding.UTF8.GetString(decryptedData)}");

            Console.ReadKey();
        }
    }
}
