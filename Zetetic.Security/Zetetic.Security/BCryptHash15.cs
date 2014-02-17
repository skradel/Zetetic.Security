using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace Zetetic.Security
{
    public class BCryptHash15 : BCryptHash
    {
        public BCryptHash15()
            : base()
        {
            _logRounds = 15;
        }
    }
}
