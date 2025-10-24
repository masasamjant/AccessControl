using Masasamjant.AccessControl.Authorization;

namespace Masasamjant.AccessControl.Web.Authorization
{
    /// <summary>
    /// Context of <see cref="AuthorizationMiddleware"/>.
    /// </summary>
    public class AuthorizationMiddlewareContext : IAccessControlWebContext
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthorizationMiddlewareContext"/> class.
        /// </summary>
        /// <param name="authorizer">The <see cref="IAuthorizer"/>.</param>
        /// <param name="urlProvider">The <see cref="IAccessControlUrlProvider"/>.</param>
        /// <param name="principalStore">The <see cref="AccessControlPrincipalStore"/>.</param>
        public AuthorizationMiddlewareContext(IAuthorizer authorizer, IAccessControlUrlProvider urlProvider, AccessControlPrincipalStore principalStore)
        {
            Authorizer = authorizer;
            UrlProvider = urlProvider;
            PrincipalStore = principalStore;
        }

        /// <summary>
        /// Gets the <see cref="IAuthorizer"/>.
        /// </summary>
        public IAuthorizer Authorizer { get; }

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
