using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace Zetetic.Security
{
    public class BCryptHash : KeyedHashAlgorithm
    {
        private System.IO.MemoryStream _ms;

        public BCryptHash()
        {
            this.Key = new byte[16];
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            (_ms = _ms ?? new System.IO.MemoryStream()).Write(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            var arr = _ms.ToArray();

            _ms = null;

            return Encoding.ASCII.GetBytes(
                BCrypt.HashPassword(Convert.ToBase64String(arr), BCrypt.GetSaltFromExternal(this.Key)));
        }

        public override void Initialize()
        {
            _ms = null;
        }
    }
}
