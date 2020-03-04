using System;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using OpenSSL.Crypto;
using UnityEngine;

namespace Security
{
    public static class Decipher
    {
        public static byte[] DecodeFile(string pathIn, string password, Cipher cipher,
            bool isEncyptedTextBase64 = false, bool isPbkdf2Used = true)
        {
            string magic = "Salted__";
            const int PKCS5_SALT_LEN = 8;
            byte[] input;

            if (isEncyptedTextBase64)
            {
                input = Convert.FromBase64String(File.ReadAllText(pathIn));
            }
            else
            {
                var base64 = Convert.ToBase64String(File.ReadAllBytes(pathIn));
                input = Convert.FromBase64String(base64);
            }

            byte[] salt = new byte[PKCS5_SALT_LEN];
            byte[] msg = new byte[input.Length - magic.Length - PKCS5_SALT_LEN];
            Buffer.BlockCopy(input, magic.Length, salt, 0, salt.Length);
            Buffer.BlockCopy(input, magic.Length + PKCS5_SALT_LEN, msg, 0, msg.Length);

            using (CipherContext cc = new CipherContext(cipher))
            {
                byte[] key = new byte[32];
                byte[] iv = new byte[16];
                byte[] pwd = Encoding.ASCII.GetBytes(password);

                if (!isPbkdf2Used)
                {
                    key = cc.BytesToKey(MessageDigest.SHA256, salt, pwd, 1, out iv);
                }
                else
                {
                    byte[] derived = Pbkdf2Sha256GetBytes(32, pwd, salt, 1000);
                    key = derived;
                    for (int i = 0; i < 16; i++)
                    {
                        iv[i] = derived[i];
                    }
                }
               
                byte[] output = cc.Decrypt(msg, key, iv);
                return output;
            }
        }

        private static byte[] Pbkdf2Sha256GetBytes(int dklen, byte[] password, byte[] salt, int iterationCount)
        {
            using (var hmac = new HMACSHA256(password))
            {
                int hashLength = hmac.HashSize / 8;
                if ((hmac.HashSize & 7) != 0)
                    hashLength++;
                int keyLength = dklen / hashLength;
                if ((long) dklen > (0xFFFFFFFFL * hashLength) || dklen < 0)
                    throw new ArgumentOutOfRangeException("dklen");
                if (dklen % hashLength != 0)
                    keyLength++;
                byte[] extendedkey = new byte[salt.Length + 4];
                Buffer.BlockCopy(salt, 0, extendedkey, 0, salt.Length);
                using (var ms = new System.IO.MemoryStream())
                {
                    for (int i = 0; i < keyLength; i++)
                    {
                        extendedkey[salt.Length] = (byte) (((i + 1) >> 24) & 0xFF);
                        extendedkey[salt.Length + 1] = (byte) (((i + 1) >> 16) & 0xFF);
                        extendedkey[salt.Length + 2] = (byte) (((i + 1) >> 8) & 0xFF);
                        extendedkey[salt.Length + 3] = (byte) (((i + 1)) & 0xFF);
                        byte[] u = hmac.ComputeHash(extendedkey);
                        Array.Clear(extendedkey, salt.Length, 4);
                        byte[] f = u;
                        for (int j = 1; j < iterationCount; j++)
                        {
                            u = hmac.ComputeHash(u);
                            for (int k = 0; k < f.Length; k++)
                            {
                                f[k] ^= u[k];
                            }
                        }

                        ms.Write(f, 0, f.Length);
                        Array.Clear(u, 0, u.Length);
                        Array.Clear(f, 0, f.Length);
                    }

                    byte[] dk = new byte[dklen];
                    ms.Position = 0;
                    ms.Read(dk, 0, dklen);
                    ms.Position = 0;
                    for (long i = 0; i < ms.Length; i++)
                    {
                        ms.WriteByte(0);
                    }

                    Array.Clear(extendedkey, 0, extendedkey.Length);
                    return dk;
                }
            }
        }

        public static bool ByteArrayToFile(string fileName, in byte[] byteArray)
        {
            try
            {
                using (var fs = new FileStream(fileName, FileMode.Create, FileAccess.Write))
                {
                    fs.Write(byteArray, 0, byteArray.Length);
                    fs.Flush();
                    fs.Close();
                    return true;
                }
            }
            catch (Exception ex)
            {
                Debug.Log("Exception caught in process: " + ex);
                return false;
            }
        }
    }
}