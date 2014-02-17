using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace Zetetic.Security
{
    public class Pbkdf2Hash256K : Pbkdf2Hash
    {
        public Pbkdf2Hash256K()
            : base()
        {
            this.WorkFactor = 256000;
        }
    }
}
