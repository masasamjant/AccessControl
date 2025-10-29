using Microsoft.Extensions.Logging;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authenticator that authenticates tokens.
    /// </summary>
    public sealed class AuthenticationTokenAuthenticator : Authenticator, IAuthenticationTokenAuthenticator
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationTokenAuthenticator"/> class.
        /// </summary>
        /// <param name="authority">The <see cref="IAccessControlAuthority"/>.</param>
        public AuthenticationTokenAuthenticator(IAccessControlAuthority authority)
            : base(authority)
        { }

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
            {
                WriteLogMessage("Authentication token was not valid.", LogLevel.Information);
                throw new AuthenticationException("Authentication token is not valid.", token);
            }

            try
            {
                var validation = Authority.ItemValidator.IsValidToken(token);

                if (!validation.IsValid)
                {
                    var message = string.IsNullOrWhiteSpace(validation.UnvalidReason) ? "Authentication token is not valid." : validation.UnvalidReason;
                    WriteLogMessage(message, LogLevel.Information);
                    throw new AuthenticationException(message, token);
                }
                
                if (!token.Identity.IsAuthenticated)
                {
                    WriteLogMessage("Identity is not authenticated.", LogLevel.Information);
                    return new AuthenticationResultResponse(null, Authority.Name);
                }

                if (!Authority.IsAuthoring(token.Identity))
                {
                    WriteLogMessage("Identity is not authored by current authority.", LogLevel.Information);
                    return new AuthenticationResultResponse(null, Authority.Name);
                }

                var principal = await AccessControlPrincipalFactory.CreateAsync(token.Identity, Authority, token.AuthenticationScheme);

                return new AuthenticationResultResponse(principal, Authority.Name);
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
