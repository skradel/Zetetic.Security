using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace Zetetic.Security
{
    public class BCryptHash16 : BCryptHash
    {
        public BCryptHash16()
            : base()
        {
            _logRounds = 16;
        }
    }
}
