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
    }
}
