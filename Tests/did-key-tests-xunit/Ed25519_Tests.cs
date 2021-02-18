using System;
using Xunit;
using ed25519;

namespace Ed25519
{
    public class Ed25519_Tests
    {
        //[Fact]
        //public void Generate_From_No_Seed()
        //{
        //    //Arrange
        //    var ed25519KeyGenerator = new Ed25519KeyPair();
        //    byte[] random = new byte[0];
        //    NSec.Cryptography.RandomGenerator.Default.GenerateBytes(random);

        //    KeyPairOptions options = new KeyPairOptions()
        //    {
        //        SecureRamdom = random
        //    };

        //    //Act
        //    var keyPair = ed25519KeyGenerator.Generate(options);

        //    //Assert
        //    Assert.NotEmpty(keyPair.Id);
        //    Assert.Matches(keyPair.Type, "Ed25519VerificationKey2018");
        //    Assert.NotEmpty(keyPair.Controller);
        //    Assert.NotEmpty(keyPair.PublicKeyMultibase);
        //}

        [Fact]
        public void Generate_From_Random_Seed()
        {
            //Arrange
            var ed25519KeyGenerator = new Ed25519KeyPair();
            byte[] random = new byte[32];
            NSec.Cryptography.RandomGenerator.Default.GenerateBytes(random);

            KeyPairOptions options = new KeyPairOptions()
            {
                SecureRamdom = random
            };

            //Act
            var keyPair = ed25519KeyGenerator.Generate(options);

            //Assert
            Assert.NotEmpty(keyPair.Id);
            Assert.Matches(keyPair.Type, "Ed25519VerificationKey2018");
            Assert.NotEmpty(keyPair.Controller);
            Assert.NotEmpty(keyPair.PublicKeyMultibase);
        }
    }
}
