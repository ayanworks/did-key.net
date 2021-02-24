using ed25519;
using SimpleBase;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DidCore
{
    public sealed class KeyPair
    {
        public string Id { get; }
        public string PublicKey { get; }

        public string PrivateKey { get; }
        public string FingerPrint { get; }

        public KeyPair(Ed25519KeyPair ed25519KeyPair)
        {
            this.Id = ed25519KeyPair.Id;
            this.PublicKey = Base58.Bitcoin.Encode(ed25519KeyPair.PublicKeyBuffer);
            this.PrivateKey = Base58.Bitcoin.Encode(ed25519KeyPair.PrivateKeyBuffer);
            this.FingerPrint = ed25519KeyPair.fingerprint();
        }
    }
}
