using Masasamjant.Security.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authentication
{
    public class AuthenticationChallengeAuthenticator
    {
        private readonly Authority authority;
        private readonly IHashProvider hashProvider;
        private readonly IAuthenticationRequestRepository requestRepository;
        private readonly IUserProvider userProvider;

        public AuthenticationChallengeAuthenticator(Authority authority, IHashProvider hashProvider, IAuthenticationRequestRepository requestRepository, IUserProvider userProvider)
        {
            this.authority = authority;
            this.hashProvider = hashProvider;
            this.requestRepository = requestRepository;
            this.userProvider = userProvider;
        }

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

        public async Task<AuthenticationResultResponse> AuthenticateChallengeAsync(AuthenticationChallenge challenge)
        {
            if (!authority.IsAuthoring(challenge))
                throw new ArgumentException($"The challenge is not authored by '{authority.Name}' authority.", nameof(challenge));

            try
            {
                var request = await requestRepository.GetAuthenticationRequestAsync(challenge.RequestIdentifier);

                if (request == null)
                    return new AuthenticationResultResponse();

                // Get identity secret if empty, then identity has no secret and authentication is not possible.
                var secret = await userProvider.GetUserSecretAsync(request.Identity.Name, request.SecretType);

                if (secret == null || secret.Data.Length == 0)
                    return new AuthenticationResultResponse();

                var requestChallenge = request.CreateAuthenticationChallenge(secret.Data, hashProvider);

                // Compare that challnges has equal data.
                if (challenge.Data.Length == requestChallenge.Data.Length)
                {
                    for (int index = 0; index < challenge.Data.Length; index++)
                    {
                        if (challenge.Data[index] != requestChallenge.Data[index])
                            return new AuthenticationResultResponse();
                    }

                    var user = await userProvider.GetUserAsync(request.Identity.Name);

                    if (user == null)
                        return new AuthenticationResultResponse();

                    var identity = new AuthoredIdentity(request.Authority, request.Identity.Name, user);
                    var principal = new AuthoredPrincipal(identity);
                    return new AuthenticationResultResponse(principal);
                }

                return new AuthenticationResultResponse();

            }
            catch (Exception exception)
            {
                throw new InvalidOperationException($"Authenticating challenge for request '{challenge.RequestIdentifier}' failed. See inner exception.", exception);
            }
        }
    }
}
