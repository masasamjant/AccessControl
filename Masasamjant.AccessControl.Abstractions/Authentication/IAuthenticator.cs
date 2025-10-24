namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authenticator that is associated with <see cref="IAccessControlAuthority"/>.
    /// </summary>
    public interface IAuthenticator
    {
        /// <summary>
        /// Gets the <see cref="IAccessControlAuthority"/>.
        /// </summary>
        IAccessControlAuthority Authority { get; }
    }
}
