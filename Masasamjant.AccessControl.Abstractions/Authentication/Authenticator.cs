namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents abtract authenticator that is associated with <see cref="IAccessControlAuthority"/>.
    /// </summary>
    public abstract class Authenticator : IAuthenticator
    {
        /// <summary>
        /// Initializes new instance of the <see cref="Authenticator"/> class.
        /// </summary>
        /// <param name="authority">The <see cref="IAccessControlAuthority"/>.</param>
        protected Authenticator(IAccessControlAuthority authority)
        {
            Authority = authority;
        }

        /// <summary>
        /// Gets the <see cref="IAccessControlAuthority"/>.
        /// </summary>
        public IAccessControlAuthority Authority { get; }
    }
}
