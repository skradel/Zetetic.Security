using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace Zetetic.Security
{
    public class BCryptHash14 : BCryptHash
    {
        public BCryptHash14()
            : base()
        {
            _logRounds = 14;
        }
    }
}
