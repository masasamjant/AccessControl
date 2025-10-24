using Masasamjant.Security.Abstractions;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents process to perform authentication using challenge.
    /// </summary>
    public sealed class ChallengeAuthenticationProcess
    {
        private readonly IAccessControlAuthority authority;
        private readonly IAuthenticationChallengeAuthenticator authenticator;
        private readonly IAuthenticationSecretProvider identitySecretProvider;
        private readonly IHashProvider hashProvider;
        private readonly string authenticationScheme;

        /// <summary>
        /// Initializes new instance of the <see cref="ChallengeAuthenticationProcess"/> class.
        /// </summary>
        /// <param name="authenticator">The <see cref="IAuthenticationChallengeAuthenticator"/>.</param>
        /// <param name="identitySecretProvider">The <see cref="IAuthenticationSecretProvider"/>.</param>
        /// <param name="hashProvider">The <see cref="IHashProvider"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <exception cref="ArgumentException">If authority of <paramref name="authenticator"/> does not support scheme specified by <paramref name="authenticationScheme"/>.</exception>
        public ChallengeAuthenticationProcess(IAuthenticationChallengeAuthenticator authenticator, IAuthenticationSecretProvider identitySecretProvider, IHashProvider hashProvider, string authenticationScheme)
        {
            if (!authenticator.Authority.IsSupportedAuthentication(authenticationScheme))
                throw new ArgumentException("The authentication scheme is not supported by authority.", nameof(authenticationScheme));

            this.authority = authenticator.Authority;
            this.authenticator = authenticator;
            this.identitySecretProvider = identitySecretProvider;
            this.hashProvider = hashProvider;
            this.authenticationScheme = authenticationScheme;
        }

        /// <summary>
        /// Authenticate specified <see cref="AccessControlIdentity"/> using authentication challenge.
        /// </summary>
        /// <param name="identity">The <see cref="AccessControlIdentity"/> to authenticate.</param>
        /// <returns>A <see cref="AuthenticationResultResponse"/>.</returns>
        public async Task<AuthenticationResultResponse> AuthenticateAsync(AccessControlIdentity identity)
        {
            var request = authority.CreateAuthenticationRequest(identity, authenticationScheme);
            var requestResponse = await authenticator.RequestAuthenticationAsync(request);

            if (!requestResponse.IsValid)
                return new AuthenticationResultResponse(null, authority);

            var identitySecret = await identitySecretProvider.GetAuthenticationSecretAsync(identity, authenticationScheme);
            var challenge = requestResponse.Request.CreateAuthenticationChallenge(identitySecret, hashProvider);
            var resultResponse = await authenticator.AuthenticateChallengeAsync(challenge);

            if (!resultResponse.IsValid)
                return new AuthenticationResultResponse(null, authority);

            return resultResponse;
        }
    }
}
