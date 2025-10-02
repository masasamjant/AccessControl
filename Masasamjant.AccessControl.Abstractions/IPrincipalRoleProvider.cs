namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents component that provides roles assigned to <see cref="AccessControlPrincipal"/>.
    /// </summary>
    public interface IPrincipalRoleProvider
    {
        /// <summary>
        /// Gets names of roles assigned to specified principal if principal has valid authenticated identity.
        /// </summary>
        /// <param name="principal">The <see cref="AccessControlPrincipal"/>.</param>
        /// <returns>A names of roles assigned to principal.</returns>
        IEnumerable<string> GetPrincipalRoles(AccessControlPrincipal principal);
    }
}
