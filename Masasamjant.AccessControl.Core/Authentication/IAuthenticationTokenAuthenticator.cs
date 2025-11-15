namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents an authenticator which can authenticate authentication tokens.
    /// </summary>
    public interface IAuthenticationTokenAuthenticator
    {
        /// <summary>
        /// Authenticates the provided authentication token.
        /// </summary>
        /// <param name="authenticationToken">The authentication token string.</param>
        /// <returns>A <see cref="AuthenticationResultResponse"/>.</returns>
        /// <exception cref="AuthenticationException">If authenticating <paramref name="authenticationToken"/> fails.</exception>
        Task<AuthenticationResultResponse> AuthenticateTokenAsync(string authenticationToken);
    }
}
