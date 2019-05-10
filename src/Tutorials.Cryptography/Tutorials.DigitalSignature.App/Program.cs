using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Tutorials.DigitalSignature.App
{
    class Program
    {
        // TODO: DO NOT DO THIS!! Store these in your certificate store
        private static Func<X509Certificate2> GetPrivateAssymetricKeyCert = () => new X509Certificate2(Convert.FromBase64String(Globals.PrivateCertData), "testing");
        public static Func<X509Certificate2> GetPublicAssymetricKeyCert = () => new X509Certificate2(Convert.FromBase64String(Globals.PublicCertData));

        static async Task Main(string[] args)
        {
            var data = Encoding.UTF8.GetBytes("Hello World!");
            var signature = GetPrivateAssymetricKeyCert().GetRSAPrivateKey().SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            Console.WriteLine($"Signature: {Convert.ToBase64String(signature)}");

            var isValidSignature = GetPublicAssymetricKeyCert().GetRSAPublicKey().VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            if (isValidSignature)
            {
                Console.WriteLine("Signature is valid!");
            }
            else
            {
                Console.WriteLine("INVALID SIGNATURE!!");
            }

            Console.ReadKey();
        }
    }
}
