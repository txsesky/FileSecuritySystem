using System;
using System.Globalization;
using System.IO;
using System.Text;
using OpenSSL.Crypto;
using UnityEngine;

namespace Security.Usage
{
    public class DecoderTest : MonoBehaviour
    {
        void Start()
        {
            var pathIn = Path.Combine(Application.streamingAssetsPath, "000000000001.jjj");
            var pathOut = Path.Combine(Application.streamingAssetsPath, "decoded001.json");
            var password = "$2y$10$C8qElkVYGafeZfAoWhwcG.O9Hfs068mXXGV5tnFd1CEbLwHUyphJ2";
            
            var time = Time.realtimeSinceStartup;
            
            byte[] decodedBytes = Decipher.DecodeFile(pathIn, password, Cipher.AES_256_CBC, false, false);
            
            print(Decipher.ByteArrayToFile(pathOut, decodedBytes).ToString());
            
            print((Time.realtimeSinceStartup - time).ToString(CultureInfo.InvariantCulture));
        }
    }
}