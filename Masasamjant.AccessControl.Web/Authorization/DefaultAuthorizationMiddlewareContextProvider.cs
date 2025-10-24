using Masasamjant.AccessControl.Authorization;

namespace Masasamjant.AccessControl.Web.Authorization
{
    /// <summary>
    /// Represents default <see cref="IAuthorizationMiddlewareContextProvider"/> implementation.
    /// </summary>
    public sealed class DefaultAuthorizationMiddlewareContextProvider : IAuthorizationMiddlewareContextProvider
    {
        private readonly IAuthorizer authorizer;
        private readonly IAccessControlUrlProvider urlProvider;
        private readonly AccessControlPrincipalStore principalStore;

        /// <summary>
        /// Initializes new instance of the <see cref="DefaultAuthorizationMiddlewareContextProvider"/> class.
        /// </summary>
        public DefaultAuthorizationMiddlewareContextProvider(IAuthorizer authorizer, IAccessControlUrlProvider urlProvider, AccessControlPrincipalStore principalStore)
        {
            this.authorizer = authorizer;
            this.urlProvider = urlProvider;
            this.principalStore = principalStore;
        }

        /// <summary>
        /// Gets the <see cref="AuthorizationMiddlewareContext"/> for <see cref="AuthorizationMiddleware"/>.
        /// </summary>
        /// <returns>A <see cref="AuthorizationMiddlewareContext"/>.</returns>
        public AuthorizationMiddlewareContext GetAuthorizationContext()
        {
            return new AuthorizationMiddlewareContext(authorizer, urlProvider, principalStore);
        }
    }
}
