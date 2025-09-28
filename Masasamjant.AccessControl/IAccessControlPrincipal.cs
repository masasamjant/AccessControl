namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents access control principal
    /// </summary>
    public interface IAccessControlPrincipal
    {
        /// <summary>
        /// Gets the <see cref="IAccessControlIdentity"/> of this principal.
        /// </summary>
        /// <returns>A <see cref="IAccessControlIdentity"/>.</returns>
        IAccessControlIdentity GetAccessControlIdentity();

        /// <summary>
        /// Gets the claims of this principal.
        /// </summary>
        /// <returns>A claims of the principal.</returns>
        IEnumerable<AccessControlClaim> GetClaims();
    }
}
