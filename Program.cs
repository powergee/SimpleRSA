using System;
using System.Numerics;
using System.Security.Cryptography;

namespace RSA_Implementation
{
    class Program
    {
        static void Main(string[] args)
        {
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            for (int i = 0; i < 1; ++i)
            {
                byte[] bytes = new byte[100];
                rng.GetBytes(bytes);
                RSAKeyPair key = RSA.GenerateKeyPair(2048);

                Console.WriteLine("[E]");
                Console.WriteLine(Convert.ToBase64String(key.Public.E.ToByteArray()));

                Console.WriteLine("[D]");
                Console.WriteLine(Convert.ToBase64String(key.Private.D.ToByteArray()));

                Console.WriteLine("[N]");
                Console.WriteLine(Convert.ToBase64String(key.Public.N.ToByteArray()));

                Console.WriteLine("[Plain]");
                Console.WriteLine(Convert.ToBase64String(bytes));

                byte[] enc = RSA.Encrypt(bytes, key.Public);

                Console.WriteLine("[Encrypted]");
                Console.WriteLine(Convert.ToBase64String(enc));

                byte[] dec = RSA.Decrypt(enc, key.Private);

                Console.WriteLine("[Decrypted]");
                Console.WriteLine(Convert.ToBase64String(dec));
            }
        }
    }
}
