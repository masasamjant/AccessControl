namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents an authenticator which can authenticate authentication challenges.
    /// </summary>
    public interface IAuthenticationChallengeAuthenticator
    {
        /// <summary>
        /// Begin authentication process by requesting authentication for the specified authentication request.
        /// </summary>
        /// <param name="request">The authentication request.</param>
        /// <returns>A <see cref="AuthenticationRequestResponse"/>.</returns>
        /// <exception cref="ArgumentException">If authority associated with authenticator is not authoring <paramref name="request"/>.</exception>
        /// <exception cref="InvalidOperationException">If requesting authentication using <paramref name="request"/> fails.</exception>
        Task<AuthenticationRequestResponse> RequestAuthenticationAsync(AuthenticationRequest request);

        /// <summary>
        /// Authenticates the specified authentication challenge. The challenge should be created based on an authentication request 
        /// previously created by <see cref="RequestAuthenticationAsync(AuthenticationRequest)"/>.
        /// </summary>
        /// <param name="challenge">The authentication challenge to authenticate.</param>
        /// <returns>A <see cref="AuthenticationResultResponse"/>.</returns>
        /// <exception cref="ArgumentException">If authority associate with authenticator is not authoring <paramref name="challenge"/>.</exception>
        /// <exception cref="InvalidOperationException">If authenticating <paramref name="challenge"/> fails.</exception>
        Task<AuthenticationResultResponse> AuthenticateChallengeAsync(AuthenticationChallenge challenge);
    }
}
