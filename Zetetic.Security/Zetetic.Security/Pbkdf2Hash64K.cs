using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace Zetetic.Security
{
    public class Pbkdf2Hash64K : Pbkdf2Hash
    {
        public Pbkdf2Hash64K()
            : base()
        {
            this.WorkFactor = 64000;
        }
    }
}
