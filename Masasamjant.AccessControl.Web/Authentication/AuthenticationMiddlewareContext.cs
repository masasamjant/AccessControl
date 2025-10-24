using Masasamjant.AccessControl.Authentication;

namespace Masasamjant.AccessControl.Web.Authentication
{
    /// <summary>
    /// Context of <see cref="AuthenticationMiddleware"/>.
    /// </summary>
    public class AuthenticationMiddlewareContext : IAccessControlWebContext
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationMiddlewareContext"/> class.
        /// </summary>
        /// <param name="authenticator">The <see cref="IAuthenticationTokenAuthenticator"/>.</param>
        /// <param name="urlProvider">The <see cref="IAccessControlUrlProvider"/>.</param>
        /// <param name="principalStore">The <see cref="AccessControlPrincipalStore"/>.</param>
        public AuthenticationMiddlewareContext(IAuthenticationTokenAuthenticator authenticator, IAccessControlUrlProvider urlProvider, AccessControlPrincipalStore principalStore)
        {
            Authenticator = authenticator;
            UrlProvider = urlProvider;
            PrincipalStore = principalStore;
        }

        /// <summary>
        /// Gets the <see cref="IAuthenticationTokenAuthenticator"/>.
        /// </summary>
        public IAuthenticationTokenAuthenticator Authenticator { get; }

        /// <summary>
        /// Gets the <see cref="IAccessControlUrlProvider"/>.
        /// </summary>
        public IAccessControlUrlProvider UrlProvider { get; }

        /// <summary>
        /// Gets the <see cref="AccessControlPrincipalStore"/>.
        /// </summary>
        public AccessControlPrincipalStore PrincipalStore { get; }
    }
}
