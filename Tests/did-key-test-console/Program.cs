using System;
using Newtonsoft.Json;
using ed25519;
using System.Text;

namespace did_key_test_console
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            byte[] random = new byte[32];
            NSec.Cryptography.RandomGenerator.Default.GenerateBytes(random);

            KeyPairOptions options = new KeyPairOptions()
            {
                SecureRamdom = random
            };

            Ed25519KeyPair keyPair = new Ed25519KeyPair().Generate(options);

            Console.WriteLine("\n\n"+JsonConvert.SerializeObject(keyPair));

            Ed25519KeyPair SignkeyPair = new Ed25519KeyPair();
            SignkeyPair.PrivateKeyBuffer = keyPair.PrivateKeyBuffer;
            //string privateKey = Base58.Bitcoin.Encode(keyPair.PrivateKeyBuffer);
            string messgae = "Hello world";
            byte[] Signature = SignkeyPair.sign(messgae);

            Ed25519KeyPair verifykeyPair = new Ed25519KeyPair();
            verifykeyPair.PublicKeyBuffer = keyPair.PublicKeyBuffer;
            Console.WriteLine("Signature: {0}", Encoding.UTF8.GetString(Signature));
            bool IsVerified = verifykeyPair.verify(messgae, Signature);

            Console.WriteLine("IsVerified: {0}", IsVerified);

        }
    }
}
