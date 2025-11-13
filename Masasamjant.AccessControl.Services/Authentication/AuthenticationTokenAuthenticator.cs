using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authentication
{
    public sealed class AuthenticationTokenAuthenticator : IAuthenticationTokenAuthenticator
    {
        private readonly Authority authority;
        private readonly IAuthenticationTokenBuilder tokenBuilder;
        private readonly IUserProvider propertiesProvider;

        public AuthenticationTokenAuthenticator(Authority authority, IAuthenticationTokenBuilder tokenBuilder, IUserProvider propertiesProvider)
        {
            this.authority = authority;
            this.tokenBuilder = tokenBuilder;
            this.propertiesProvider = propertiesProvider;
        }

        public async Task<AuthenticationResultResponse> AuthenticateTokenAsync(string authenticationToken)
        {
            var token = await tokenBuilder.BuildAuthenticationTokenAsync(authenticationToken, authority);

            if (token == null || !authority.IsAuthoring(token))
                return new AuthenticationResultResponse();

            try
            {
                if (token.IsAuthenticated)
                {
                    var user = await propertiesProvider.GetUserAsync(token.Identity.Name);

                    if (user == null)
                        return new AuthenticationResultResponse();

                    var identity = new AuthoredIdentity(authority, token.Identity.Name, user);
                    var principal = new AuthoredPrincipal(identity);
                    return new AuthenticationResultResponse(principal);
                }

                return new AuthenticationResultResponse();
            }
            catch (Exception exception)
            {
                throw new InvalidOperationException($"Authenticating challenge for request '{token.Identifier}' failed. See inner exception.", exception);
            }
        }
    }
}
