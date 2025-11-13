using Masasamjant.Security.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents an authenticator which can authenticate authentication challenges.
    /// </summary>
    public sealed class AuthenticationChallengeAuthenticator : IAuthenticationChallengeAuthenticator
    {
        private readonly Authority authority;
        private readonly IHashProvider hashProvider;
        private readonly IAuthenticationRequestRepository requestRepository;
        private readonly IUserProvider userProvider;

        /// <summary>
        /// Initializes new instance of <see cref="AuthenticationChallengeAuthenticator"/> class.
        /// </summary>
        /// <param name="authority">The authority.</param>
        /// <param name="hashProvider">The hash provider.</param>
        /// <param name="requestRepository">The repository to store authentication request.</param>
        /// <param name="userProvider">The user provider.</param>
        public AuthenticationChallengeAuthenticator(Authority authority, IHashProvider hashProvider, IAuthenticationRequestRepository requestRepository, IUserProvider userProvider)
        {
            this.authority = authority;
            this.hashProvider = hashProvider;
            this.requestRepository = requestRepository;
            this.userProvider = userProvider;
        }

        /// <summary>
        /// Begin authentication process by requesting authentication for the specified authentication request.
        /// </summary>
        /// <param name="request">The authentication request.</param>
        /// <returns>A <see cref="AuthenticationRequestResponse"/>.</returns>
        /// <exception cref="ArgumentException">If authority associated with authenticator is not authoring <paramref name="request"/>.</exception>
        /// <exception cref="InvalidOperationException">If requesting authentication using <paramref name="request"/> fails.</exception>
        public async Task<AuthenticationRequestResponse> RequestAuthenticationAsync(AuthenticationRequest request)
        {
            if (!authority.IsAuthoring(request))
                throw new ArgumentException($"The request is not authored by '{authority.Name}' authority.", nameof(request));
            try
            {
                var response = new AuthenticationRequestResponse(request);
                await requestRepository.SaveAuthenticationRequestAsync(request);
                return response;
            }
            catch (Exception exception)
            {
                throw new InvalidOperationException($"Saving authentication request '{request.Identifier}' failed. See inner exception.", exception);
            }
        }

        /// <summary>
        /// Authenticates the specified authentication challenge. The challenge should be created based on an authentication request 
        /// previously created by <see cref="RequestAuthenticationAsync(AuthenticationRequest)"/>.
        /// </summary>
        /// <param name="challenge">The authentication challenge to authenticate.</param>
        /// <returns>A <see cref="AuthenticationResultResponse"/>.</returns>
        /// <exception cref="ArgumentException">If authority associate with authenticator is not authoring <paramref name="challenge"/>.</exception>
        /// <exception cref="InvalidOperationException">If authenticating <paramref name="challenge"/> fails.</exception>
        public async Task<AuthenticationResultResponse> AuthenticateChallengeAsync(AuthenticationChallenge challenge)
        {
            if (!authority.IsAuthoring(challenge))
                throw new ArgumentException($"The challenge is not authored by '{authority.Name}' authority.", nameof(challenge));

            try
            {
                // No data in challenge, cannot authenticate.
                if (challenge.Data.Length == 0)
                    return new AuthenticationResultResponse();

                var request = await requestRepository.GetAuthenticationRequestAsync(challenge.RequestIdentifier);

                if (request == null)
                    return new AuthenticationResultResponse();

                // First get user by identity name.
                var user = await userProvider.GetUserAsync(request.Identity.Name);

                // No such user exists.
                if (user == null)
                    return new AuthenticationResultResponse();

                // Get user secret. If null or no data, then user has no secret and authentication is not possible.
                var secret = await userProvider.GetUserSecretAsync(request.Identity.Name, request.SecretType);

                if (secret == null || secret.Data.Length == 0)
                    return new AuthenticationResultResponse();

                // Create challenge to compare to provided challenge.
                var requestChallenge = request.CreateAuthenticationChallenge(secret, hashProvider);

                // Compare that challnges has equal data.
                if (challenge.Data.Length == requestChallenge.Data.Length)
                {
                    for (int index = 0; index < challenge.Data.Length; index++)
                    {
                        // Challange data differ, return unauthenticated response.
                        if (challenge.Data[index] != requestChallenge.Data[index])
                            return new AuthenticationResultResponse();
                    }

                    // Challenges has equal data. Create identity and principal
                    var identity = new AuthoredIdentity(request.Authority, request.Identity.Name, user);
                    var principal = new AuthoredPrincipal(identity);

                    // Return authenticated response.
                    return new AuthenticationResultResponse(principal);
                }

                // Challenges data length differ, return unauthenticated response.
                return new AuthenticationResultResponse();

            }
            catch (Exception exception)
            {
                throw new InvalidOperationException($"Authenticating challenge for request '{challenge.RequestIdentifier}' failed. See inner exception.", exception);
            }
        }
    }
}
