namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Reprents factory to create authentication token string for <see cref="AccessControlPrincipal"/>.
    /// </summary>
    public interface IAuthenticationTokenFactory
    {
        /// <summary>
        /// Creates authentication token string for access control principal.
        /// </summary>
        /// <param name="principal">The <see cref="AccessControlPrincipal"/>.</param>
        /// <returns>A authentication token string.</returns>
        string CreateAuthenticationToken(AccessControlPrincipal principal);
    }
}
