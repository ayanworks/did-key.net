using System;
using System.Threading.Tasks;
using NSec.Cryptography;
using Multiformats.Base;

namespace ed25519
{
    public class Ed25519KeyPair
    {
        public string Id { get; set; }
        public string Type { get; set; }
        public string Controller { get; set; }
        public string PublicKeyMultibase { get; set; }

        public Ed25519KeyPair()
        {
        }

        public Ed25519KeyPair(string id, string controller)
        {
            Type = "Ed25519VerificationKey2018";
            Id = id;
            Controller = controller;
        }

        public Ed25519KeyPair Generate(KeyPairOptions options)
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

            const KeyBlobFormat privateKeyBlob = KeyBlobFormat.NSecPrivateKey;
            const KeyBlobFormat publicKeyBlob = KeyBlobFormat.NSecPublicKey;

            byte[] secretKey = key.Export(privateKeyBlob);
            byte[] publicKey = key.Export(publicKeyBlob);

            string privateKeyBase58 = Multibase.Encode(MultibaseEncoding.Base58Btc, secretKey);
            string publicKeyBase58 = Multibase.Encode(MultibaseEncoding.Base58Btc, publicKey);

            Console.WriteLine($"privateKeyBase58 :${privateKeyBase58}");
            Console.WriteLine($"publicKeyBase58 :${publicKeyBase58}");

            string didRaw = fingerprintFromPublicKey(publicKeyBase58);
            string did = String.Format("did:key:{0}", didRaw);
            string keyId = String.Format("#{0}", didRaw);

            return new Ed25519KeyPair
            {
                Id = keyId,
                Controller = did,
                Type = "Ed25519VerificationKey2018",
                PublicKeyMultibase = publicKeyBase58
            };
        }

        private KeyCreationParameters createPolicy()
        {
            KeyExportPolicies policy = KeyExportPolicies.AllowPlaintextExport;
            return new KeyCreationParameters() { ExportPolicy = policy };
        }

        public string fingerprintFromPublicKey(string publicKeyBase58)
        {
            byte[] pubkeyBytes = null;

            if (!String.IsNullOrEmpty(publicKeyBase58))
            {
                pubkeyBytes = Multibase.Decode(publicKeyBase58, out MultibaseEncoding encoding);
            }
            // ed25519 cryptonyms are multicodec encoded values, specifically:
            // (multicodec ed25519-pub 0xed01 + key bytes)

            byte[] buffer = new byte[2 + pubkeyBytes.Length];
            buffer[0] = (byte)0xed;
            buffer[1] = (byte)0x01;
            //buffer.SetValue(pubkeyBytes, 2);
            pubkeyBytes.CopyTo(buffer, 2);
            // prefix with `z` to indicate multi-base base58btc encoding
            return String.Format("z{0}", Multibase.Encode(MultibaseEncoding.Base58Btc, buffer));
        }

        //public Func<T> signer() 
        // {
        //     if (!this.privateKeyBuffer)
        //     {
        //         throw new Error("No private key to sign with.");
        //     }
        //     var ( privateKeyBuffer ) = this;
        //     return sign();
        // }

        // async byte[] sign(string data)
        // {
        //     const string signatureUInt8Array = "";//algo_Ed25519.sign(this.PrivateKeyBuffer, data);
        //     return signatureUInt8Array;
        // }

    }
}