namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents provider of <see cref="IAccessControlPrincipal"/>.
    /// </summary>
    public interface IAccessControlPrincipalProvider
    {
        /// <summary>
        /// Gets <see cref="IAccessControlPrincipal"/> by name.
        /// </summary>
        /// <param name="name">The principal name.</param>
        /// <returns>A <see cref="IAccessControlPrincipal"/> or <c>null</c>, if not exist.</returns>
        IAccessControlPrincipal? GetAccessControlPrincipal(string name);
    }
}
