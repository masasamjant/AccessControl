namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authenticator that authenticates challenges.
    /// </summary>
    public interface IAuthenticationChallengeAuthenticator
    {
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
        Task<AuthenticationRequestResponse> RequestAuthenticationAsync(AuthenticationRequest request);

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
        Task<AuthenticationResultResponse> AuthenticateChallengeAsync(AuthenticationChallenge challenge);
    }
}
