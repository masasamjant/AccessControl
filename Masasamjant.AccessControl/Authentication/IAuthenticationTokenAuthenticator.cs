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
        /// <param name="token">The <see cref="AuthenticationToken"/>.</param>
        /// <returns>A <see cref="AuthenticationResultResponse"/>.</returns>
        /// <exception cref="AuthenticationException">
        /// If <paramref name="token"/> is not valid.
        /// -or-
        /// If authentication process fails.
        /// </exception>
        AuthenticationResultResponse AuthenticateToken(AuthenticationToken token);
    }
}
