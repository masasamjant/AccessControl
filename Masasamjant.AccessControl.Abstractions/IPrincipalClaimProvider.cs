namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents component that provides claims for <see cref="AccessControlPrincipal"/>.
    /// </summary>
    public interface IPrincipalClaimProvider
    {
        /// <summary>
        /// Gets claims for specified principal if principal has valid authenticated identity.
        /// </summary>
        /// <param name="principal">The <see cref="AccessControlPrincipal"/>.</param>
        /// <returns>A claims of principal.</returns>
        IEnumerable<AccessControlClaim> GetPrincipalClaims(AccessControlPrincipal principal);
    }
}
