using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace Masasamjant.AccessControl
{
    public class JWTProperties
    {
        public JWTProperties(string signKey)
            : this(signKey, SecurityAlgorithms.HmacSha384)
        { }

        public JWTProperties(string signKey, string signAlgorithm)
        {
            SignKey = signKey;
            SignAlgorithm = signAlgorithm;
        }

        public string SignKey { get; }

        public string SignAlgorithm { get; }
    }
}
