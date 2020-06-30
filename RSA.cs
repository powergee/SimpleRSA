using System;
using System.Numerics;
using System.Security.Cryptography;

namespace RSA_Implementation
{
    public class RSAPublic
    {
        public BigInteger N { get; }
        public BigInteger E { get; }

        public RSAPublic(BigInteger n, BigInteger e)
        {
            N = n;
            E = e;
        }
    }

    public class RSAPrivate
    {
        public BigInteger N { get; }
        public BigInteger D { get; }

        public RSAPrivate(BigInteger n, BigInteger d)
        {
            N = n;
            D = d;
        }
    }

    public class RSAKeyPair
    {
        public RSAPublic Public { get; }
        public RSAPrivate Private { get; }

        public RSAKeyPair(RSAPublic pub, RSAPrivate pri)
        {
            Public = pub;
            Private = pri;
        }
    }

    public static class RSA
    {
        public static RSAKeyPair GenerateKeyPair(int keySize)
        {
            BigInteger p = GetRandomPrime(keySize / 2);
            BigInteger q = GetRandomPrime(keySize / 2);
            BigInteger n = p * q;
            BigInteger pi = (p-1) * (q-1);
            BigInteger e = 65537;
            BigInteger d = ModInverse(e, pi);

            return new RSAKeyPair(new RSAPublic(n, e), new RSAPrivate(n, d));
        }

        public static byte[] Encrypt(byte[] plain, RSAPublic pub)
        {
            BigInteger plainInt = new BigInteger(plain);
            BigInteger cipherInt = BigInteger.ModPow(plainInt, pub.E, pub.N);
            return cipherInt.ToByteArray();
        }

        public static byte[] Decrypt(byte[] cipher, RSAPrivate pri)
        {
            BigInteger cipherInt = new BigInteger(cipher);
            BigInteger plainInt = BigInteger.ModPow(cipherInt, pri.D, pri.N);
            return plainInt.ToByteArray();
        }

        private static void ExtendedGCD(BigInteger a, BigInteger b, out BigInteger x, out BigInteger y)
        {
            if (a % b == 0)
            {
                x = 0;
                y = 1;
            }
            else
            {
                BigInteger subX, subY;
                ExtendedGCD(b, a % b, out subX, out subY);
                x = subY;
                y = subX - (subY * (a / b));
            }
        }

        private static BigInteger ModInverse(BigInteger value, BigInteger mod)
        {
            BigInteger x, y;
            ExtendedGCD(value, mod, out x, out y);
            if (x < 0)
                x += mod;
            
            return x % mod;
        }

        private static BigInteger GetRandomPrime(int bitCount)
        {
            BigInteger prime;
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            int byteLength = bitCount / 8 + (bitCount % 8 > 0 ? 1 : 0);
            do
            {
                byte[] bytes = new byte[byteLength];
                rng.GetBytes(bytes);
                prime = new BigInteger(bytes);
            } while (!IsProbablyPrime(prime, 40));
            
            rng.Dispose();
            return prime;
        }

        private static bool IsProbablyPrime(BigInteger target, int repeat)
        {
            if (target == 2 || target == 3)
                return true;
            if (target < 2 || target % 2 == 0)
                return false;

            BigInteger d = target - 1;
            int s = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                ++s;
            }

            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            byte[] bytes = new byte[target.ToByteArray().LongLength];
            BigInteger a;

            for (int i = 0; i < repeat; ++i)
            {
                do
                {
                    rng.GetBytes(bytes);
                    a = new BigInteger(bytes);
                } while (a < 2 || a >= target - 2);

                BigInteger x = BigInteger.ModPow(a, d, target);
                if (x == 1 || x == target - 1)
                    continue;
                
                for (int r = 1; r < s; ++r)
                {
                    x = BigInteger.ModPow(x, 2, target);
                    if (x == 1)
                        return false;
                    if (x == target - 1)
                        break;
                }

                if (x != target - 1)
                    return false;
            }

            rng.Dispose();
            return true;
        }
    }
}
