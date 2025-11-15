namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents an authenticator which can authenticate authentication tokens.
    /// </summary>
    public sealed class AuthenticationTokenAuthenticator : IAuthenticationTokenAuthenticator
    {
        private readonly Authority authority;
        private readonly AuthenticationTokenBuilder tokenBuilder;
        private readonly IUserProvider propertiesProvider;

        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationTokenAuthenticator"/> class.
        /// </summary>
        /// <param name="authority">The authority.</param>
        /// <param name="tokenBuilder">The authentication token builder.</param>
        /// <param name="propertiesProvider">The user provider.</param>
        public AuthenticationTokenAuthenticator(Authority authority, AuthenticationTokenBuilder tokenBuilder, IUserProvider propertiesProvider)
        {
            this.authority = authority;
            this.tokenBuilder = tokenBuilder;
            this.propertiesProvider = propertiesProvider;
        }

        /// <summary>
        /// Authenticates the provided authentication token.
        /// </summary>
        /// <param name="authenticationToken">The authentication token string.</param>
        /// <returns>A <see cref="AuthenticationResultResponse"/>.</returns>
        /// <exception cref="AuthenticationException">If authenticating <paramref name="authenticationToken"/> fails.</exception>
        public async Task<AuthenticationResultResponse> AuthenticateTokenAsync(string authenticationToken)
        {
            if (string.IsNullOrWhiteSpace(authenticationToken))
                return new AuthenticationResultResponse();

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
                    var updatedAuthenticationToken = new AuthenticationToken(identity);
                    var updatedToken = await tokenBuilder.BuildAuthenticationTokenAsync(updatedAuthenticationToken);
                    return new AuthenticationResultResponse(principal, updatedToken);
                }

                return new AuthenticationResultResponse();
            }
            catch (Exception exception)
            {
                throw new AuthenticationException($"Authenticating challenge for request '{token.Identifier}' failed. See inner exception.", exception);
            }
        }
    }
}
