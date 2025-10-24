namespace Masasamjant.AccessControl.Web
{
    /// <summary>
    /// Represents default implementation of <see cref="AccessControlPrincipalStore"/> that stores 
    /// <see cref="AccessControlPrincipal"/> into HTTP request items.
    /// </summary>
    public sealed class DefaultAccessControlPrincipalStore : AccessControlPrincipalStore
    {
        private readonly string accessControlPrincipalKey;

        /// <summary>
        /// Initializes new instance of the <see cref="DefaultAccessControlPrincipalStore"/> class.
        /// </summary>
        /// <param name="accessControlPrincipalKey">The key to store principal in HTTP context items.</param>
        public DefaultAccessControlPrincipalStore(string accessControlPrincipalKey)
        {
            this.accessControlPrincipalKey = accessControlPrincipalKey;
        }

        /// <summary>
        /// Gets the stored <see cref="AccessControlPrincipal"/>.
        /// </summary>
        /// <param name="httpContext">The <see cref="HttpContext"/>.</param>
        /// <param name="accessControlContext">The <see cref="IAccessControlWebContext"/>.</param>
        /// <returns>A stored <see cref="AccessControlPrincipal"/> or <c>null</c>.</returns>
        protected override Task<AccessControlPrincipal?> GetStoredPrincipalAsync(HttpContext httpContext, IAccessControlWebContext accessControlContext)
        {
            return Task.FromResult(httpContext.Items[accessControlPrincipalKey] as AccessControlPrincipal);
        }

        /// <summary>
        /// Store <see cref="AccessControlPrincipal"/>.
        /// </summary>
        /// <param name="principal">The <see cref="AccessControlPrincipal"/>.</param>
        /// <param name="httpContext">The <see cref="HttpContext"/>.</param>
        /// <param name="accessControlContext">The <see cref="IAccessControlWebContext"/>.</param>
        protected override Task StorePrincipalAsync(AccessControlPrincipal principal, HttpContext httpContext, IAccessControlWebContext accessControlContext)
        {
            httpContext.Items[accessControlPrincipalKey] = principal;
            return Task.CompletedTask;
        }
    }
}
