using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace Zetetic.Security
{
    public class PBKDF2Hash : KeyedHashAlgorithm
    {
        private static readonly int s_iter;
        private const int kHashBytes = 20, kSaltLength = 16;

        private System.IO.MemoryStream ms;

        public int WorkFactor { get; set; }

        /// <summary>
        /// Attempt to read the PBKDF2 work factor from the HKLM:Software\Zetetic LLC\Security\WorkFactor
        /// </summary>
        static PBKDF2Hash()
        {
            s_iter = 5000;
            
            try
            {
                using (var reg = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Zetetic LLC\Security"))
                {
                    object p = reg.GetValue(@"WorkFactor");

                    if (p != null)
                    {
                        if (p is int || p is long)
                        {
                            s_iter = (int)p;
                        }
                        else if (!string.Empty.Equals(p))
                        {
                            s_iter = Convert.ToInt32(p);   
                        }
                    }
                }
            }
            catch (System.Exception e)
            {
                System.Diagnostics.Debug.Write(string.Format("Failed to init from registry; {0} {1}", e.GetType(), e.Message));
            }
        }


        public PBKDF2Hash()
            : base()
        {
            this.WorkFactor = s_iter;
            this.Key = new byte[kSaltLength];
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
            (ms = ms ?? new System.IO.MemoryStream()).Write(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            if (this.Key == null || this.Key.Length == 0)
            {
                throw new CryptographicException("Missing KeyedAlgorithm key");
            }

            ms.Flush();

            var arr = ms.ToArray();

            ms = null;

            var pb = new Rfc2898DeriveBytes(arr, this.Key, this.WorkFactor);

            return pb.GetBytes(kHashBytes);
        }

        public override void Initialize()
        {
            ms = new System.IO.MemoryStream();
        }
    }
}
