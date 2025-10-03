namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authenticator that authenticates tokens.
    /// </summary>
    public interface IAuthenticationTokenAuthenticator
    {
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
        Task<AuthenticationResultResponse> AuthenticateTokenAsync(string authenticationToken);
    }
}
