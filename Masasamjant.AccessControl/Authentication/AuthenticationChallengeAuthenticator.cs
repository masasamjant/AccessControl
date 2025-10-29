using Masasamjant.Security.Abstractions;
using Microsoft.Extensions.Logging;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authentication challenge authenticator.
    /// </summary>
    public sealed class AuthenticationChallengeAuthenticator : Authenticator, IAuthenticationChallengeAuthenticator
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationChallengeAuthenticator"/> class.
        /// </summary>
        /// <param name="authority">The <see cref="AccessControlAuthority"/>.</param>
        /// <param name="hashProvider">The <see cref="IHashProvider"/>.</param>
        public AuthenticationChallengeAuthenticator(IAccessControlAuthority authority, IHashProvider hashProvider, IAuthenticationRequestRepository authenticationRequestRepository)
            : base(authority)
        {
            HashProvider = hashProvider;
            RequestRepository = authenticationRequestRepository;
        }

        private IHashProvider HashProvider { get; }

        private IAuthenticationRequestRepository RequestRepository { get; }

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
        public async Task<AuthenticationRequestResponse> RequestAuthenticationAsync(AuthenticationRequest request)
        {
            // Check that request is valid.
            if (!request.IsValid)
            {
                var message = "Authentication request is not valid.";
                WriteLogMessage(message, LogLevel.Information);
                throw new AuthenticationException(message, request);
            }

            WriteLogMessage($"Authentication request '{request.Identifier}'.", LogLevel.Information);

            // Check that request is authorized.
            if (!Authority.IsAuthoring(request))
            {
                var message = $"Authentication request '{request.Identifier}' is not authorized by '{Authority.Name}' authority.";
                WriteLogMessage(message, LogLevel.Information);
                throw new AuthenticationException(message, request);
            }

            try
            {
                // Perform additional request validation.
                var validation = Authority.ItemValidator.IsValidRequest(request);

                if (!validation.IsValid)
                {
                    var message = string.IsNullOrWhiteSpace(validation.UnvalidReason) ? "Authentication request is not valid" : validation.UnvalidReason;
                    WriteLogMessage(message, LogLevel.Information);
                    throw new AuthenticationException(message, request);
                }

                // Check if authority is authoring specified identity.
                if (!Authority.IsAuthoring(request.Identity))
                {
                    WriteLogMessage($"Authority is not authoring the '{request.Identity.Name}' identity.", LogLevel.Information);
                    return new AuthenticationRequestResponse();
                }

                // Create valid response.
                var response = new AuthenticationRequestResponse(request);

                // Save authentication request for later.
                await RequestRepository.SaveAuthenticationRequestAsync(request);

                WriteLogMessage($"Response created for '{request.Identifier}' authentication request.", LogLevel.Information);

                // Return response.
                return response;
            }
            catch (Exception exception)
            {
                WriteLogMessage(exception.Message, LogLevel.Error);
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
        public async Task<AuthenticationResultResponse> AuthenticateChallengeAsync(AuthenticationChallenge challenge)
        {
            // Check that challenge is valid.
            if (!challenge.IsValid)
            {
                var message = "Authentication challenge is not valid.";
                WriteLogMessage(message, LogLevel.Information);
                throw new AuthenticationException(message, challenge);
            }

            // Check that challenge is authorized.
            if (!Authority.IsAuthoring(challenge))
            {
                var message = $"Authentication challenge '{challenge.Identifier}' is not authorized by '{Authority.Name}' authority.";
                WriteLogMessage(message, LogLevel.Information);
                throw new AuthenticationException(message, challenge);
            }
            // Check data challenge contains data.
            if (challenge.Data.Length == 0)
            {
                var message = $"Authentication challenge '{challenge.Identifier}' has empty data.";
                WriteLogMessage(message, LogLevel.Information);
                throw new AuthenticationException(message, challenge);
            }
            try
            {
                // Perform additional challenge validation.
                var validation = Authority.ItemValidator.IsValidChallenge(challenge);

                if (!validation.IsValid)
                {
                    var message = string.IsNullOrWhiteSpace(validation.UnvalidReason) ? "Authentication challenge is not valid." : validation.UnvalidReason;
                    WriteLogMessage(message, LogLevel.Information);
                    throw new AuthenticationException(message, challenge);
                }

                // Get request saved that match this challenge.
                var request = await RequestRepository.GetAuthenticationRequestAsync(challenge.Identifier);

                // No such request, return unauthenticated response.
                if (request == null || string.IsNullOrWhiteSpace(request.Identity.Name))
                {
                    WriteLogMessage($"No authentication request found for '{challenge.Identifier}' challenge.", LogLevel.Information);
                    return new AuthenticationResultResponse(null, Authority.Name);
                }
                // Gets the authentication secret.
                var secret = await Authority.GetAuthenticationSecretAsync(request.Identity, request.AuthenticationScheme);

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
                        {
                            WriteLogMessage("Challenge data not match. Challenge unauthenticated.", LogLevel.Information);
                            return new AuthenticationResultResponse(null, Authority.Name);
                        }
                    }
                    var identity = new AccessControlIdentity(request.Identity.Name, true, request.AuthenticationScheme, Authority.Name);

                    if (!identity.IsAuthenticated)
                    {
                        WriteLogMessage($"Identity '{identity.Name}' not authenticated.", LogLevel.Information);
                        return new AuthenticationResultResponse(null, Authority.Name);
                    }

                    var principal = await AccessControlPrincipalFactory.CreateAsync(identity, Authority, request.AuthenticationScheme);

                    WriteLogMessage($"Challenge '{challenge.Identifier}' authenticated.", LogLevel.Information);

                    return new AuthenticationResultResponse(principal, Authority.Name);
                }

                // Challenges not with same data return unauthenticated response.
                return new AuthenticationResultResponse(null, Authority.Name);
            }
            catch (Exception exception)
            {
                WriteLogMessage(exception.Message, LogLevel.Error);
                if (exception is AuthenticationException)
                    throw;
                else
                    throw new AuthenticationException("Could not authenticate challenge. See inner exception.", challenge, exception);
            }
        }
    }
}
