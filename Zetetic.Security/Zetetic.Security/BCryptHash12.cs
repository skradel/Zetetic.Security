using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace Zetetic.Security
{
    public class BCryptHash12 : BCryptHash
    {
        public BCryptHash12()
            : base()
        {
            _logRounds = 12;
        }
    }
}
