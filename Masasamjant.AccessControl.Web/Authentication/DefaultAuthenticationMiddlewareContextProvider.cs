using Masasamjant.AccessControl.Authentication;

namespace Masasamjant.AccessControl.Web.Authentication
{
    /// <summary>
    /// Represents default <see cref="IAuthenticationMiddlewareContextProvider"/> implementation.
    /// </summary>
    public sealed class DefaultAuthenticationMiddlewareContextProvider : IAuthenticationMiddlewareContextProvider
    {
        private readonly IAuthenticationTokenAuthenticator authenticator;
        private readonly IAccessControlUrlProvider urlProvider;
        private readonly AccessControlPrincipalStore principalStore;

        /// <summary>
        /// Initializes new instance of the <see cref="DefaultAuthenticationMiddlewareContextProvider"/> class.
        /// </summary>
        public DefaultAuthenticationMiddlewareContextProvider(IAuthenticationTokenAuthenticator authenticator, IAccessControlUrlProvider urlProvider, AccessControlPrincipalStore principalStore)
        {
            this.authenticator = authenticator;
            this.urlProvider = urlProvider;
            this.principalStore = principalStore;
        }

        /// <summary>
        /// Gets the <see cref="AuthenticationMiddlewareContext"/> for <see cref="AuthenticationMiddleware"/>.
        /// </summary>
        /// <returns>A <see cref="AuthenticationMiddlewareContext"/>.</returns>
        public AuthenticationMiddlewareContext GetAuthenticationContext()
        {
            return new AuthenticationMiddlewareContext(authenticator, urlProvider, principalStore);
        }
    }
}
