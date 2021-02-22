using System;
using System.Text;
using System.Threading.Tasks;
using NSec.Cryptography;
//using Multiformats.Base;
using SimpleBase;

namespace ed25519
{
 
    public sealed class Ed25519KeyPair
    {
        public string Id { get; set; }
        public string Type { get; set; }
        public string Controller { get; set; }
        public byte[] PublicKeyBuffer { get; set; }
        public byte[] PrivateKeyBuffer { get; set; }

        public Ed25519KeyPair()
        {
        }

        //public Ed25519KeyPair(string id, string controller)
        //{
        //    Type = "Ed25519VerificationKey2018";
        //    Id = id;
        //    Controller = controller;
        //}
        public Ed25519KeyPair(KeyPairOptions options)
        {
            this.Type = "Ed25519VerificationKey2018";
            this.Id = options.Id;
            this.Controller = options.Controller;
            if (!string.IsNullOrEmpty(options.PublicKeyBase58))
            {
                this.PublicKeyBuffer = Base58.Bitcoin.Decode(options.PublicKeyBase58).ToArray();
            }
            else
            {
                throw new Exception(
                  "Ed25519KeyPair requires publicKeyBase58 or publicKeyJwk, recieved neither."
                );
            }

            if (!string.IsNullOrEmpty(options.PrivateKeyBase58))
            {
                this.PrivateKeyBuffer = Base58.Bitcoin.Decode(options.PrivateKeyBase58).ToArray();
            }

            if (!string.IsNullOrEmpty(this.Controller) && !(string.IsNullOrEmpty(this.Id)))
            {
                this.Id = string.Format("{0}#{1}", this.Controller, this.fingerprint());
            }
        }

        public Ed25519KeyPair Generate(KeyPairOptions? options)
        {
            Key key;
            //if (options.SecureRamdom != null /*&& options.SecureRamdom.Length > 0*/)
            //{
            //    key = Key.Create(SignatureAlgorithm.Ed25519, createPolicy());
            //}
            //else
            //{
            //    throw new Exception("options.secureRandom is required.");
            //}

            key = Key.Create(SignatureAlgorithm.Ed25519, createPolicy());

            const KeyBlobFormat privateKeyBlob = KeyBlobFormat.RawPrivateKey;
            const KeyBlobFormat publicKeyBlob = KeyBlobFormat.RawPublicKey;

            byte[] secretKey = key.Export(privateKeyBlob);
            byte[] publicKey = key.Export(publicKeyBlob);

            string privateKeyBase58 = Base58.Bitcoin.Encode(secretKey);
            string publicKeyBase58 = Base58.Bitcoin.Encode(publicKey);

            Console.WriteLine($"privateKeyBase58 : {privateKeyBase58}");
            Console.WriteLine($"publicKeyBase58 : {publicKeyBase58}");

            string didRaw = fingerprintFromPublicKey(publicKeyBase58);

            string did = String.Format("did:key:{0}", didRaw);
            Console.WriteLine("did: {0}", did);

            string keyId = String.Format("#{0}", didRaw);
            Console.WriteLine("keyId: {0}", keyId);
           
            return new Ed25519KeyPair(new KeyPairOptions
            {
                Id = keyId,
                Controller = did,
                PublicKeyBase58 = publicKeyBase58,
                PrivateKeyBase58 = privateKeyBase58
            });
        }

        private KeyCreationParameters createPolicy()
        {
            KeyExportPolicies policy = KeyExportPolicies.AllowPlaintextExport;
            return new KeyCreationParameters() { ExportPolicy = policy };
        }

        public string fingerprint()
        {
            return Ed25519KeyPair.fingerprintFromPublicKey(Base58.Bitcoin.Encode(this.PublicKeyBuffer));
        }
        public static string fingerprintFromPublicKey(string publicKeyBase58)
        {
            byte[] pubkeyBytes = null;

            if (!String.IsNullOrEmpty(publicKeyBase58))
            {
                pubkeyBytes = Base58.Bitcoin.Decode(publicKeyBase58).ToArray();
            }
            // ed25519 cryptonyms are multicodec encoded values, specifically:
            // (multicodec ed25519-pub 0xed01 + key bytes)

            byte[] buffer = new byte[2 + pubkeyBytes.Length];
            buffer[0] = (byte)0xed;
            buffer[1] = (byte)0x01;
            //buffer.SetValue(pubkeyBytes, 2);
            pubkeyBytes.CopyTo(buffer, 2);
            // prefix with `z` to indicate multi-base base58btc encoding
            return String.Format("z{0}", Base58.Bitcoin.Encode(buffer));
        }

        public byte[] sign(string data)
        {
            if (this.PrivateKeyBuffer==null)
            {
                throw new Exception("No private key to sign with.");
            }
            //Key keypair1 = new Key(SignatureAlgorithm.Ed25519, createPolicy());
            Key keypair = Key.Import(SignatureAlgorithm.Ed25519, this.PrivateKeyBuffer, KeyBlobFormat.RawPrivateKey, createPolicy());
             byte[] signatureUInt8Array = SignatureAlgorithm.Ed25519.Sign(keypair, Encoding.UTF8.GetBytes(data));
            return signatureUInt8Array;
        }

        public bool verify(string data,byte[] signature)
        {
            if (this.PublicKeyBuffer == null)
            {
                throw new Exception("No public key to verify with.");
            }
            PublicKey publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, this.PublicKeyBuffer, KeyBlobFormat.RawPublicKey);
            bool isValid = SignatureAlgorithm.Ed25519.Verify(publicKey, Encoding.UTF8.GetBytes(data), signature);
            return isValid;
        }

       
    }
}