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

            byte[] bytes = new byte[100];
            rng.GetBytes(bytes);
            RSAKeyPair key = RSA.GenerateKeyPair(2048);

            Console.Write("[E]: ");
            Console.WriteLine(Convert.ToBase64String(key.Public.E.ToByteArray()) + "\n");

            Console.Write("[D]: ");
            Console.WriteLine(Convert.ToBase64String(key.Private.D.ToByteArray()) + "\n");

            Console.Write("[N]: ");
            Console.WriteLine(Convert.ToBase64String(key.Public.N.ToByteArray()) + "\n");

            Console.WriteLine("[Plain]");
            Console.WriteLine(Convert.ToBase64String(bytes) + "\n");

            byte[] enc = RSA.Encrypt(bytes, key.Public);

            Console.WriteLine("[Encrypted]");
            Console.WriteLine(Convert.ToBase64String(enc) + "\n");

            byte[] dec = RSA.Decrypt(enc, key.Private);

            Console.WriteLine("[Decrypted]");
            Console.WriteLine(Convert.ToBase64String(dec) + "\n");

            bool isSame = bytes.Length == dec.Length;
            for (int j = 0; j < bytes.Length && isSame; ++j)
                if (bytes[j] != dec[j])
                    isSame = false;

            if (isSame)
                Console.WriteLine("평문과 복호문이 같습니다.\n");
            else
                Console.WriteLine("평문과 복호문이 다릅니다.\n");
        }
    }
}
