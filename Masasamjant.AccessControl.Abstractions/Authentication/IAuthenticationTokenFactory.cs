namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents factory to create authentication token string for <see cref="AccessControlPrincipal"/>.
    /// </summary>
    public interface IAuthenticationTokenFactory
    {
        /// <summary>
        /// Creates authentication token string for access control principal.
        /// </summary>
        /// <param name="principal">The <see cref="AccessControlPrincipal"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns>A authentication token string.</returns>
        Task<string> CreateAuthenticationTokenAsync(AccessControlPrincipal principal, string authenticationScheme);

        /// <summary>
        /// Creates <see cref="AuthenticationToken"/> from specified authentication token string.
        /// </summary>
        /// <param name="authenticationTokenString">The authentication token string.</param>
        /// <returns>A <see cref="AuthenticationToken"/>.</returns>
        Task<AuthenticationToken> CreateAuthenticationTokenAsync(string authenticationTokenString);
    }
}
