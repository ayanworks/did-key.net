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

        public byte[] PublicKeyBuffer { get; set; }
        public byte[] PrivateKeyBuffer { get; set; }

        public Ed25519KeyPair()
        {

        }

        public Ed25519KeyPair(string id, string controller)
        {
            Type = "Ed25519VerificationKey2018";
            Id = id;
            Controller = controller;
        }

        static async Ed25519KeyPair Generate(bool secureRandom)
        {
            Key key;
            if (secureRandom)
            {
                using var key = Key.Create(SignatureAlgorithm.Ed25519, createPolicy());
                
            }
            else
            {
                throw new Error("options.secureRandom is required.");
            }

            var p = key.ExportPolicy;

            KeyBlobFormat pkf = KeyBlobFormat.NSecPrivateKey;
            KeyBlobFormat pubkf = KeyBlobFormat.NSecPublicKey;

            var secretKey = key.Export(pkf);
            var publicKey = key.Export(pubkf);

            const string privateKeyBase58 = Multibase.Encode(MultibaseEncoding.Base58Btc, pk);
            const string publicKeyBase58 = Multibase.Encode(MultibaseEncoding.Base58Btc, pubk);

            //const publicKeyBase58 = bs58.encode(key.publicKey);
            //const privateKeyBase58 = bs58.encode(key.secretKey);

            string didRaw = Ed25519KeyPair.fingerprintFromPublicKey(publicKeyBase58);
            const string did = String.Format("did:key:{0}", didRaw);
            const string keyId = String.Format("#", didRaw);

            return new Ed25519KeyPair{
                          Id= keyId,
                          Controller= did,
                          publicKeyBase58,
                          privateKeyBase58
                        };
        }

        static async string fingerprintFromPublicKey(string publicKeyBase58, string privateKeyBase58)
        {
            string pubkeyBytes;

            if (publicKeyBase58)
            {
                pubkeyBytes = Multibase.Decode(MultibaseEncoding.Base58Btc, pubk);
            }          
            // ed25519 cryptonyms are multicodec encoded values, specifically:
            // (multicodec ed25519-pub 0xed01 + key bytes)

            byte[] buffer = new byte(2 + pubkeyBytes.length);
            buffer[0] = 0xed;
            buffer[1] = 0x01;
            buffer.set(pubkeyBytes, 2);
            // prefix with `z` to indicate multi-base base58btc encoding
            return String.Format("z{0}",Multibase.Encode(MultibaseEncoding.Base58Btc, buffer));
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
       //     const string signatureUInt8Array = "";//ed25519.sign(this.PrivateKeyBuffer, data);
       //     return signatureUInt8Array;
       // }

    }
}
