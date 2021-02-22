using System;
using NSec.Cryptography;

namespace ed25519
{
    public class KeyPairOptions
    {
#pragma warning disable CS8632 // The annotation for nullable reference types should only be used in code within a '#nullable' annotations context.
        public byte[]? SecureRamdom { get; set; }
#pragma warning restore CS8632 // The annotation for nullable reference types should only be used in code within a '#nullable' annotations context.

        public KeyPairOptions()
        {
        }

        public string Id { get; set; }
        public string Type { get; set; }

        public string Controller { get; set; }
        public string PublicKeyBase58 { get; set; }
        public string PrivateKeyBase58 { get; set; }

       
    }
}
