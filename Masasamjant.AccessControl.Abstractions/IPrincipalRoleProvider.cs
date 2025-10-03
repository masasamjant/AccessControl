namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents component that provides roles assigned to <see cref="AccessControlPrincipal"/>.
    /// </summary>
    public interface IPrincipalRoleProvider
    {
        /// <summary>
        /// Gets roles assigned to specified principal if principal has valid authenticated identity.
        /// </summary>
        /// <param name="principal">The <see cref="AccessControlPrincipal"/>.</param>
        /// <returns>A roles assigned to principal.</returns>
        Task<IEnumerable<AccessControlRole>> GetPrincipalRolesAsync(AccessControlPrincipal principal);
    }
}
