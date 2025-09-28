using Masasamjant.Security.Abstractions;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents abstact authenticator that implements both <see cref="IAuthenticationChallengeAuthenticator"/> and <see cref="IAuthenticationTokenAuthenticator"/> interfaces.
    /// </summary>
    public abstract class Authenticator : IAuthenticationChallengeAuthenticator, IAuthenticationTokenAuthenticator
    {
        /// <summary>
        /// Initializes new instance of the <see cref="Authenticator"/> class.
        /// </summary>
        /// <param name="principalProvider">The <see cref="IAccessControlPrincipalProvider"/>.</param>
        /// <param name="hashProvider">The <see cref="IHashProvider"/>.</param>
        /// <param name="secretProvider">The <see cref="IAuthenticationSecretProvider"/>.</param>
        protected Authenticator(IAccessControlPrincipalProvider principalProvider, IHashProvider hashProvider, IAuthenticationSecretProvider secretProvider)
        {
            PrincipalProvider = principalProvider;
            HashProvider = hashProvider;
            SecretProvider = secretProvider;
        }

        /// <summary>
        /// Gets the <see cref="IAccessControlPrincipalProvider"/>.
        /// </summary>
        protected IAccessControlPrincipalProvider PrincipalProvider { get; }

        /// <summary>
        /// Gets the <see cref="IHashProvider"/>.
        /// </summary>
        protected IHashProvider HashProvider { get; }

        /// <summary>
        /// Gets the <see cref="IAuthenticationSecretProvider"/>.
        /// </summary>
        protected IAuthenticationSecretProvider SecretProvider { get; }

        public AuthenticationRequestResponse RequestAuthentication(AuthenticationRequest request)
        {
            if (!request.IsValid)
                throw new AuthenticationException("Authentication request is not valid.", request);

            try
            {
                if (!IsValidRequest(request, out var reason))
                    throw new AuthenticationException(string.IsNullOrWhiteSpace(reason) ? "Authentication request is not valid" : reason, request);

                var principal = PrincipalProvider.GetAccessControlPrincipal(request.Identity);

                if (principal == null)
                    return new AuthenticationRequestResponse();

                var response = new AuthenticationRequestResponse(request);

                SaveAuthenticationRequest(request);

                return response;
            }
            catch (Exception exception)
            {
                if (exception is AuthenticationException)
                    throw;
                else
                    throw new AuthenticationException("Could not create authentication challenge. See inner exception.", request, exception);
            }
        }

        /// <summary>
        /// Authenticates specified <see cref="AuthenticationChallenge"/>.
        /// </summary>
        /// <param name="challenge">The <see cref="AuthenticationChallenge"/>.</param>
        /// <returns>A <see cref="AuthenticationResultResponse"/>.</returns>
        /// <exception cref="AuthenticationException">
        /// If <paramref name="challenge"/> is not valid or <see cref="AuthenticationChallenge.ChallengeString"/> is empty or whitespace.
        /// -or-
        /// If authentication process fails.
        /// </exception>
        public AuthenticationResultResponse AuthenticateChallenge(AuthenticationChallenge challenge)
        {
            if (!challenge.IsValid)
                throw new AuthenticationException("Authentication challenge is not valid.", challenge);

            if (challenge.Data.Length == 0)
                throw new AuthenticationException("Authentication challenge data is empty.", challenge);

            try
            {
                if (!IsValidChallenge(challenge, out var reason))
                    throw new AuthenticationException(string.IsNullOrWhiteSpace(reason) ? "Authentication challenge is not valid." : reason, challenge);

                var request = GetAuthenticationRequest(challenge.Identifier);

                if (request == null)
                    return new AuthenticationResultResponse(AuthenticationResult.Unauthenticated, null, null);

                var principal = PrincipalProvider.GetAccessControlPrincipal(request.Identity);

                if (principal == null)
                    return new AuthenticationResultResponse(AuthenticationResult.Unauthenticated, null, $"Principal with identity of '{request.Identity}' not found.");

                var secret = SecretProvider.GetAuthenticationSecret(request.Identity, request.AuthenticationScheme);

                var requestChallenge = request.CreateAuthenticationChallenge(secret, HashProvider);

                if (challenge.Data.Length == requestChallenge.Data.Length)
                {
                    for (int index = 0; index < challenge.Data.Length; index++)
                    {
                        if (challenge.Data[index] != requestChallenge.Data[index])
                            return new AuthenticationResultResponse(AuthenticationResult.Unauthenticated, null, null);
                    }

                    var authenticationTokenValue = PrincipalProvider.GetAuthenticationToken(principal);
                    var authenticationToken = new AuthenticationToken(authenticationTokenValue, principal.GetClaims());
                    return new AuthenticationResultResponse(AuthenticationResult.Authenticated, authenticationToken, null);
                }

                return new AuthenticationResultResponse(AuthenticationResult.Unauthenticated, null, null);
            }
            catch (Exception exception)
            {
                if (exception is AuthenticationException)
                    throw;
                else
                    throw new AuthenticationException("Could not authenticate challenge. See inner exception.", challenge, exception);
            }
        }

        /// <summary>
        /// Authenticates specified <see cref="AuthenticationToken"/>.
        /// </summary>
        /// <param name="token">The <see cref="AuthenticationToken"/>.</param>
        /// <returns>A <see cref="AuthenticationResultResponse"/>.</returns>
        /// <exception cref="AuthenticationException">
        /// If <paramref name="token"/> is not valid.
        /// -or-
        /// If authentication process fails.
        /// </exception>
        public AuthenticationResultResponse AuthenticateToken(AuthenticationToken token)
        {
            if (!token.IsValid)
                throw new AuthenticationException("Authentication token is not valid.", token);

            try
            {
                if (!IsValidToken(token, out var reason))
                    throw new AuthenticationException(string.IsNullOrWhiteSpace(reason) ? "Authentication token is not valid." : reason, token);

                var identity = PrincipalProvider.GetAccessControlPrincipal(token);

                if (identity == null)
                    return new AuthenticationResultResponse(AuthenticationResult.Unauthenticated, null, null);

                token.Refresh();

                return new AuthenticationResultResponse(AuthenticationResult.Authenticated, token, null);
            }
            catch (Exception exception)
            {
                if (exception is AuthenticationException)
                    throw;
                else
                    throw new AuthenticationException("Could not authenticate token. See inner exception.", token, exception);
            }
        }

        /// <summary>
        /// Perform additional validation of <see cref="AuthenticationRequest"/>. Default implementation returns always <c>true</c>.
        /// </summary>
        /// <param name="request">The <see cref="AuthenticationRequest"/>.</param>
        /// <param name="invalidReason">The reason why <paramref name="request"/> is not valid like if too old.</param>
        /// <returns><c>true</c> if <paramref name="request"/> is valid; <c>false</c> otherwise.</returns>
        protected virtual bool IsValidRequest(AuthenticationRequest request, out string? invalidReason)
        {
            invalidReason = null;
            return true;
        }

        /// <summary>
        /// Perform additional validation of <see cref="AuthenticationChallenge"/>. Default implementation returns always <c>true</c>.
        /// </summary>
        /// <param name="challenge">The <see cref="AuthenticationChallenge"/>.</param>
        /// <param name="invalidReason">The reason why <paramref name="challenge"/> is not valid like if too old.</param>
        /// <returns><c>true</c> if <paramref name="challenge"/> is valid; <c>false</c> otherwise.</returns>
        protected virtual bool IsValidChallenge(AuthenticationChallenge challenge, out string? invalidReason)
        {
            invalidReason = null;
            return true;
        }

        /// <summary>
        /// Perform additional validation of <see cref="AuthenticationToken"/>. Default implementation returns always <c>true</c>.
        /// </summary>
        /// <param name="token">The <see cref="AuthenticationToken"/>.</param>
        /// <param name="invalidReason">The reason why <paramref name="token"/> is not valid like if too old.</param>
        /// <returns><c>true</c> if <paramref name="token"/> is valid; <c>false</c> otherwise.</returns>
        protected virtual bool IsValidToken(AuthenticationToken token, out string? invalidReason)
        {
            invalidReason = null;
            return true;
        }

        protected abstract void SaveAuthenticationRequest(AuthenticationRequest request);

        protected abstract AuthenticationRequest? GetAuthenticationRequest(Guid identifier);
    }
}
