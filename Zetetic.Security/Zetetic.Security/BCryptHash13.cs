using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace Zetetic.Security
{
    public class BCryptHash13 : BCryptHash
    {
        public BCryptHash13()
            : base()
        {
            _logRounds = 13;
        }
    }
}
