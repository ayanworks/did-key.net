using ed25519;
using SimpleBase;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DidCore
{
    public static class Did_Key
    {
        public static Key_Pair Generate()
        {
            var ed25519KeyGenerator = new Ed25519KeyPair();
            var ed25519KeyPair = ed25519KeyGenerator.Generate(null);
            var keyPair = new Key_Pair(ed25519KeyPair);
            return keyPair;
        }

        public static string Sign(string data, string privateKey)
        {
            var ed25519KeySigner = new Ed25519KeyPair();
            ed25519KeySigner.PrivateKeyBuffer = Base58.Bitcoin.Decode(privateKey).ToArray();
            byte[] signatureBuffer = ed25519KeySigner.sign(data);
            return Base58.Bitcoin.Encode(signatureBuffer);
        }

        public static bool Verify(string publicKey, string data, string signature)
        {
            var ed25519KeyVerifier = new Ed25519KeyPair();
            ed25519KeyVerifier.PublicKeyBuffer = Base58.Bitcoin.Decode(publicKey).ToArray();
            byte[] signatureBuffer = Base58.Bitcoin.Decode(signature).ToArray();
            bool isVerified = ed25519KeyVerifier.verify(data, signatureBuffer);
            return isVerified;
        }
    }
}
