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
        string CreateAuthenticationToken(AccessControlPrincipal principal, string authenticationScheme);
    }
}
