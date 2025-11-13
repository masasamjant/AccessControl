using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl
{
    public class AuthoredClaim : IAuthored
    {
        public AuthoredClaim(Authority authority, string claimType, string claimValue, string claimValueType)
        {
            Authority = authority;
            ClaimType = claimType;
            ClaimValue = claimValue;
            ClaimValueType = claimValueType;
        }

        public AuthoredClaim() 
        { }

        public string ClaimType { get; internal set; } = string.Empty;

        public string ClaimValue { get; internal set; } = string.Empty;

        public string ClaimValueType { get; internal set; } = string.Empty;

        public Authority Authority { get; internal set; } = new Authority();

        public Claim GetClaim()
        {
            return new Claim(ClaimType, ClaimValue, ClaimValueType, Authority.Uri.ToString());
        }
    }
}
