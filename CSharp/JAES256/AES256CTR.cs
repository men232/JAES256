//
// Based of Aes128Ctr.cs | Copyright 2011 Eli Sherer
//

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using T1.CoreUtils;

namespace JAES256
{
    public static class AES256CTR
    {
        private const int BlockSize = 16;

        public static string EncryptDefault(string inputBase64, string passphrase = null)
        {
            return DecryptDefault(inputBase64, passphrase);
        }

        public static byte[] EncryptBytes(byte[] input, byte[] Key, byte[] IV)
        {
            return DecryptBytes(input, Key, IV);
        }

        public static string DecryptDefault(string inputBase64, string passphrase = null)
        {
            byte[] key, iv;
            CryptoUtility.PassphraseToDefaultKeyAndIV(CryptoUtility.RawBytesFromString(passphrase), null, 1, out key, out iv);

            return Encoding.UTF8.GetString(DecryptBytes(Convert.FromBase64String(inputBase64), key, iv));
        }

        public static byte[] DecryptBytes(byte[] input, byte[] Key, byte[] IV)
        {
            using (RijndaelManaged cipher = new RijndaelManaged())
            {
                cipher.Key = Key;
                cipher.IV = IV;
                cipher.Mode = CipherMode.ECB;
                cipher.Padding = PaddingMode.None;

                byte[] output = new byte[input.Length];
                Buffer.BlockCopy(input, 0, output, 0, input.Length);

                TransformBlock(cipher, output, IV);

                return output;
            }
        }

        public static void TransformBlock(RijndaelManaged cipher, byte[] input, byte[] iv)
        {
            var ict = cipher.CreateEncryptor(); //reflective
            var encryptedIV = new byte[BlockSize];
            var counter = BitConverter.ToUInt64(iv.Reverse().ToArray(), 0); //get the nonce

            for (int offset = 0; offset < input.Length; offset += BlockSize, counter++)
            {
                for (int i = 0; i < 8; i++) //Push the new counter to the end of iv
                    iv[i + BlockSize - 8] = (byte)((counter >> ((7 - i) * 8)) & 0xff);
                ict.TransformBlock(iv, 0, BlockSize, encryptedIV, 0); // ECB on counter
                // Xor it with the data
                for (int i = 0; i < BlockSize && i + offset < input.Length; i++)
                    input[i + offset] ^= encryptedIV[i];
            }
        }
    }
}