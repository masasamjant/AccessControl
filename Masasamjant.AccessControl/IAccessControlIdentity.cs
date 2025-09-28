namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents identity of <see cref="IAccessControlPrincipal"/>.
    /// </summary>
    public interface IAccessControlIdentity
    {
        /// <summary>
        /// Gets the unique name of the identity.
        /// </summary>
        /// <remarks>This can be user name, email, phone number etc. what ever uniquely identifies identity in system.</remarks>
        string Name { get; }
    }
}
