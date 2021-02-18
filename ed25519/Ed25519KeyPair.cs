using System;
using System.Threading.Tasks;

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

        //public Task<void> Generate(bool secureRandom)
        //{
        //    Key key;
        //    if (secureRandom)
        //    {
        //        //key = ed25519.generateKeyPair({
        //        //    isAvailable: true,
        //        //    randomBytes: options.secureRandom,
        //        //});
        //    }

        //    return;
        //}
   
    }
}
