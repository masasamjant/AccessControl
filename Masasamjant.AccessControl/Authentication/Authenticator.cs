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
        /// <param name="authority">The <see cref="AccessControlAuthority"/>.</param>
        /// <param name="hashProvider">The <see cref="IHashProvider"/>.</param>
        protected Authenticator(AccessControlAuthority authority, IHashProvider hashProvider)
        {
            Authority = authority;
            HashProvider = hashProvider;
        }

        /// <summary>
        /// Gets the <see cref="AccessControlAuthority"/>.
        /// </summary>
        protected AccessControlAuthority Authority { get; }

        /// <summary>
        /// Gets the <see cref="IHashProvider"/>.
        /// </summary>
        protected IHashProvider HashProvider { get; }

        /// <summary>
        /// Begin authentication process by requesting authentication.
        /// </summary>
        /// <param name="request">The <see cref="AuthenticationRequest"/>.</param>
        /// <returns>A <see cref="AuthenticationRequestResponse"/>.</returns>
        /// <exception cref="AuthenticationException">
        /// If <paramref name="request"/> is not valid authentication request.
        /// -or-
        /// If authentication process fails.
        /// </exception>
        public AuthenticationRequestResponse RequestAuthentication(AuthenticationRequest request)
        {
            // Check that request is valid.
            if (!request.IsValid)
                throw new AuthenticationException("Authentication request is not valid.", request);

            // Check that request is authorized.
            if (!Authority.IsAuthoring(request))
                throw new AuthenticationException($"Authentication request is not authorized by '{Authority.Name}' authority.", request);

            try
            {
                // Perform additional request validation.
                if (!IsValidRequest(request, out var reason))
                    throw new AuthenticationException(string.IsNullOrWhiteSpace(reason) ? "Authentication request is not valid" : reason, request);

                // Check if authority is authoring specified identity.
                if (!Authority.IsAuthoring(request.Identity))
                    return new AuthenticationRequestResponse();

                // Create valid response.
                var response = new AuthenticationRequestResponse(request);

                // Save authentication request for later.
                SaveAuthenticationRequest(request);

                // Return response.
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
            // Check that challenge is valid.
            if (!challenge.IsValid)
                throw new AuthenticationException("Authentication challenge is not valid.", challenge);

            // Check that challenge is authorized.
            if (!Authority.IsAuthoring(challenge))
                throw new AuthenticationException($"Authentication challenge is not authorized by '{Authority.Name}' authority.", challenge);

            // Check data challenge contains data.
            if (challenge.Data.Length == 0)
                throw new AuthenticationException("Authentication challenge data is empty.", challenge);

            try
            {
                // Perform additional challenge validation.
                if (!IsValidChallenge(challenge, out var reason))
                    throw new AuthenticationException(string.IsNullOrWhiteSpace(reason) ? "Authentication challenge is not valid." : reason, challenge);

                // Get request saved that match this challenge.
                var request = GetAuthenticationRequest(challenge.Identifier);

                // No such request, return unauthenticated response.
                if (request == null || string.IsNullOrWhiteSpace(request.Identity.Name))
                    return new AuthenticationResultResponse(null, Authority.Name);

                // Gets the authentication secret.
                var secret = Authority.GetAuthenticationSecret(request.Identity.Name, request.AuthenticationScheme);

                // Gets the challange from saved request.
                var requestChallenge = request.CreateAuthenticationChallenge(secret, HashProvider);

                // Compare that challenges has equal data.
                if (challenge.Data.Length == requestChallenge.Data.Length)
                {
                    // Compare all data.
                    for (int index = 0; index < challenge.Data.Length; index++)
                    {
                        // If mismatch, return unauthenticated response.
                        if (challenge.Data[index] != requestChallenge.Data[index])
                            return new AuthenticationResultResponse(null, Authority.Name);
                    }

                    var identity = request.Identity;
                    identity.IsAuthenticated = true;
                    identity.AuthenticationType = request.AuthenticationScheme;
                    var principal = new AccessControlPrincipal(request.Identity);
                    var claims = Authority.GetPrincipalClaims(principal);
                    var roles = Authority.GetPrincipalRoles(principal);
                    principal.Claims = claims.ToArray();
                    principal.Roles = roles.ToArray();

                    // Data matches, get authentication token string and create authenticated response.
                    var authenticationToken = Authority.CreateAuthenticationToken(principal);
                    identity.AuthenticationToken = authenticationToken;

                    return new AuthenticationResultResponse(principal, Authority.Name);
                }

                // Challenges not with same data return unauthenticated response.
                return new AuthenticationResultResponse(null, Authority.Name);
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
        /// <param name="authenticationToken">The authentication token string from <see cref="AuthenticationToken.Identity"/>.</param>
        /// <returns>A <see cref="AuthenticationResultResponse"/>.</returns>
        /// <exception cref="AuthenticationException">
        /// If <paramref name="token"/> is not valid.
        /// -or-
        /// If authentication process fails.
        /// </exception>
        public AuthenticationResultResponse AuthenticateToken(string authenticationToken)
        {
            var token = Authority.CreateAuthenticationToken(authenticationToken);
            
            if (!token.IsValid)
                throw new AuthenticationException("Authentication token is not valid.", token);

            try
            {
                if (!IsValidToken(token, out var reason))
                    throw new AuthenticationException(string.IsNullOrWhiteSpace(reason) ? "Authentication token is not valid." : reason, token);

                if (!token.Identity.IsAuthenticated)
                    return new AuthenticationResultResponse(null, Authority.Name);

                if (!Authority.IsAuthoring(token.Identity))
                    return new AuthenticationResultResponse(null, Authority.Name);

                var principal = new AccessControlPrincipal(token.Identity);
                var claims = Authority.GetPrincipalClaims(principal);
                var roles = Authority.GetPrincipalRoles(principal);
                principal.Claims = claims.ToArray();
                principal.Roles = roles.ToArray();

                authenticationToken = Authority.CreateAuthenticationToken(principal);
                principal.Identity.AuthenticationToken = authenticationToken;
                
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

        /// <summary>
        /// Saves authentication request to be obtained later in process.
        /// </summary>
        /// <param name="request">The <see cref="AuthenticationRequest"/> to save.</param>
        protected abstract void SaveAuthenticationRequest(AuthenticationRequest request);

        /// <summary>
        /// Gets the saved <see cref="AuthenticationRequest"/>.
        /// </summary>
        /// <param name="identifier">The authentication request identifier.</param>
        /// <returns>A <see cref="AuthenticationRequest"/> or <c>null</c>, if not exist.</returns>
        protected abstract AuthenticationRequest? GetAuthenticationRequest(Guid identifier);
    }
}
