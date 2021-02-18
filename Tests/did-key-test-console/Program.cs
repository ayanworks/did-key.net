using System;
using Newtonsoft.Json;
using ed25519;

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
        }
    }
}
