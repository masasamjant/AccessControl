using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authentication
{
    public class AuthenticationResultResponse : AuthenticationResponse
    {
        public AuthenticationResultResponse(AuthoredPrincipal principal)
            : base(principal.Authority)
        {
            Principal = principal;
        }

        public AuthenticationResultResponse()
        { }

        [JsonInclude]
        public AuthoredPrincipal Principal { get; internal set; } = new AuthoredPrincipal();

        [JsonIgnore]
        public AuthenticationResult Result
        {
            get
            {
                if (Principal.Identity.IsAuthenticated)
                    return AuthenticationResult.Authenticated;

                return AuthenticationResult.Unauthenticated;
            }
        }
    }
}
