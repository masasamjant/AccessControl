namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authenticator that authenticates tokens.
    /// </summary>
    public sealed class AuthenticationTokenAuthenticator : IAuthenticationTokenAuthenticator
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationTokenAuthenticator"/> class.
        /// </summary>
        /// <param name="authority">The <see cref="IAccessControlAuthority"/>.</param>
        public AuthenticationTokenAuthenticator(IAccessControlAuthority authority)
        {
            Authority = authority;
        }

        private IAccessControlAuthority Authority { get; }

        /// <summary>
        /// Authenticates specified <see cref="AuthenticationToken"/>.
        /// </summary>
        /// <param name="authenticationToken">The authentication token string from <see cref="AuthenticationToken.Identity"/>.</param>
        /// <returns>A <see cref="AuthenticationResultResponse"/>.</returns>
        /// <exception cref="AuthenticationException">
        /// If <paramref name="token"/> is not valid.
        /// -or-
        /// If authentication process fails.
        /// </exception>
        public async Task<AuthenticationResultResponse> AuthenticateTokenAsync(string authenticationToken)
        {
            var token = await Authority.CreateAuthenticationTokenAsync(authenticationToken);

            if (!token.IsValid)
                throw new AuthenticationException("Authentication token is not valid.", token);

            try
            {
                var validation = Authority.ItemValidator.IsValidToken(token);

                if (!validation.IsValid)
                    throw new AuthenticationException(string.IsNullOrWhiteSpace(validation.UnvalidReason) ? "Authentication token is not valid." : validation.UnvalidReason, token);

                if (!token.Identity.IsAuthenticated)
                    return new AuthenticationResultResponse(null, Authority);

                if (!Authority.IsAuthoring(token.Identity))
                    return new AuthenticationResultResponse(null, Authority);

                var principal = await AccessControlPrincipal.CreateAsync(token.Identity, Authority, token.AuthenticationScheme);

                return new AuthenticationResultResponse(principal, Authority);
            }
            catch (Exception exception)
            {
                if (exception is AuthenticationException)
                    throw;
                else
                    throw new AuthenticationException("Could not authenticate token. See inner exception.", token, exception);
            }
        }
    }
}
