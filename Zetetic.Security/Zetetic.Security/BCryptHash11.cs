using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace Zetetic.Security
{
    public class BCryptHash11 : BCryptHash
    {
        public BCryptHash11()
            : base()
        {
            _logRounds = 11;
        }
    }
}
