using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using T1.CoreUtils;

namespace JAES256
{
    public class JAES256
    {
        public const int BLOCK_EXIPE_TIME = 60;

        private byte[] m_salt;

        public JAES256(string salt = "")
        {
            m_salt = this.SHA1(salt);
        }

        public byte[] SHA1(string data)
        {
            byte[] byteData = Encoding.UTF8.GetBytes(data);
            return this.SHA1(byteData);
        }

        public byte[] SHA1(byte[] data)
        {
            return System.Security.Cryptography.SHA1.Create().ComputeHash(data);
        }

        public string ToHex(byte[] data, bool withDefise = false)
        {
            string hex = BitConverter.ToString(data);

            if (!withDefise)
                hex = hex.Replace("-", string.Empty);

            return hex.ToLower();
        }

        public double GetTimestamp()
        {
            return (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
        }

        public string Encrypt(string data, string shared_key)
        {
            byte[] byteData = Encoding.UTF8.GetBytes(data);
            return Convert.ToBase64String(this.EncryptBytes(byteData, shared_key));
        }

        public string Decrypt(string inputBase64, string shared_key, bool skiptTmestamp = false)
        {
            byte[] data = Convert.FromBase64String(inputBase64);
            int exipe_on;
            return Encoding.UTF8.GetString(this.DecryptBytes(data, shared_key, skiptTmestamp, out exipe_on));
        }

        public byte[] EncryptBytes(byte[] data, string shared_key)
        {
            if (data.Length < 1)
                throw new ArgumentNullException("data should be more than 1 bytes");

            byte[] timestamp = BitConverter.GetBytes(this.GetTimestamp());
            byte[] dataBlock = new byte[28 + data.Length];

            Buffer.BlockCopy(m_salt, 0, dataBlock, 0, 20);
            Buffer.BlockCopy(timestamp, 0, dataBlock, 20, 8);
            Buffer.BlockCopy(data, 0, dataBlock, 28, data.Length);

            byte[] signature = this.SHA1(dataBlock);
            byte[] aes_key = Encoding.UTF8.GetBytes(shared_key + this.ToHex(signature).ToLower());

            byte[] key, iv;
            CryptoUtility.PassphraseToDefaultKeyAndIV(aes_key, null, 1, out key, out iv);

            byte[] encryptData = AES256CTR.EncryptBytes(dataBlock, key, iv);
            byte[] result = new byte[20 + encryptData.Length];
            Buffer.BlockCopy(signature, 0, result, 0, 20);
            Buffer.BlockCopy(encryptData, 0, result, 20, encryptData.Length);

            return result;
        }

        public byte[] DecryptBytes(byte[] data, string shared_key, bool skiptTmestamp, out int exipe_on)
        {
            if (data.Length <= 20)
                throw new ArgumentNullException("data should be more than 20 bytes");

            byte[] signature = new byte[20];
            Buffer.BlockCopy(data, 0, signature, 0, 20);

            byte[] aes_key = Encoding.UTF8.GetBytes(shared_key + this.ToHex(signature).ToLower());
            byte[] cryptData = new byte[data.Length - 20];

            Buffer.BlockCopy(data, 20, cryptData, 0, data.Length - 20);

            byte[] key, iv;
            CryptoUtility.PassphraseToDefaultKeyAndIV(aes_key, null, 1, out key, out iv);

            byte[] decryptData = AES256CTR.DecryptBytes(cryptData, key, iv);
            byte[] _slat = new byte[20];
            byte[] _timestamp = new byte[8];
            byte[] _dataBlock = new byte[decryptData.Length - 28];

            Buffer.BlockCopy(decryptData, 0, _slat, 0, 20);
            Buffer.BlockCopy(decryptData, 20, _timestamp, 0, 8);
            Buffer.BlockCopy(decryptData, 28, _dataBlock, 0, decryptData.Length - 28);

            exipe_on = Convert.ToInt32(BitConverter.ToDouble(_timestamp, 0) - GetTimestamp());

            if (ToHex(SHA1(decryptData)) != ToHex(signature))
                throw new Exception("Signature of data not valid.");
            else if (ToHex(m_salt) != ToHex(_slat))
                throw new Exception("Salt of data not valid.");
            else if (!skiptTmestamp && (exipe_on < 0 || exipe_on > BLOCK_EXIPE_TIME))
                throw new Exception("Timestamp of data has expired.");

            return _dataBlock;
        }
    }
}
