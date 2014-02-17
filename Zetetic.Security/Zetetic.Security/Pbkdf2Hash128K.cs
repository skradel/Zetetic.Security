using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace Zetetic.Security
{
    public class Pbkdf2Hash128K : Pbkdf2Hash
    {
        public Pbkdf2Hash128K()
            : base()
        {
            this.WorkFactor = 128000;
        }
    }
}
