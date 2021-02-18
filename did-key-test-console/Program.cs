using System;
using ed25519;
using Newtonsoft.Json;

namespace did_key_test_console
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            Ed25519KeyPair keyPair = ed25519.Ed25519KeyPair.Generate();

            Console.WriteLine(JsonConvert.SerializeObject(keyPair));
        }
    }
}
