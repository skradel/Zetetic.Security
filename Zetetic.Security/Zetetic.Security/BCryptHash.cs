using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace Zetetic.Security
{
    public class BCryptHash : KeyedHashAlgorithm
    {
        private const int kHashBytes = 24;

        private System.IO.MemoryStream _ms;

        public BCryptHash()
        {
            this.Key = new byte[16];
        }

        /// <summary>
        /// Hash size in bits
        /// </summary>
        public override int HashSize
        {
            get
            {
                return kHashBytes * 8;
            }
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            (_ms = _ms ?? new System.IO.MemoryStream()).Write(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            if (this.Key == null || this.Key.Length == 0)
            {
                throw new CryptographicException("Missing KeyedAlgorithm key");
            }

            _ms.Flush();

            var arr = _ms.ToArray();

            _ms = null;

            return new BCryptRaw().CryptRaw(arr, this.Key, 10);
        }

        public override void Initialize()
        {
            _ms = null;
        }
    }

    internal class BCryptRaw : BCrypt
    {
        public byte[] CryptRaw(byte[] password, byte[] salt, int logRounds)
        {
            return base.CryptRaw(password, salt, logRounds);
        }
    }
}
