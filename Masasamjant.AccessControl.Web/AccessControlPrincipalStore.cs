namespace Masasamjant.AccessControl.Web
{
    /// <summary>
    /// Represents store to save authenticated access control principal.
    /// </summary>
    public abstract class AccessControlPrincipalStore
    {
        /// <summary>
        /// Gets the authenticated <see cref="AccessControlPrincipal"/> stored using <see cref="StoreAuthenticatedPrincipal(AccessControlPrincipal, HttpContext, IAccessControlWebContext)"/>.
        /// </summary>
        /// <param name="httpContext">The <see cref="HttpContext"/>.</param>
        /// <param name="accessControlContext">The <see cref="IAccessControlWebContext"/>.</param>
        /// <returns>A authenticated <see cref="AccessControlPrincipal"/> or <c>null</c>.</returns>
        public async Task<AccessControlPrincipal?> GetAuthenticatedPrincipalAsync(HttpContext httpContext, IAccessControlWebContext accessControlContext)
        {
            var principal = await GetStoredPrincipalAsync(httpContext, accessControlContext);

            return principal.IsAuthenticatePrincipal() ? principal : null;
        }

        /// <summary>
        /// Store authenticated <see cref="AccessControlPrincipal"/> to be retrieved later 
        /// via <see cref="GetAuthenticatedPrincipal(HttpContext, IAccessControlWebContext)"/>.
        /// </summary>
        /// <param name="principal">The <see cref="AccessControlPrincipal"/>.</param>
        /// <param name="httpContext">The <see cref="HttpContext"/>.</param>
        /// <param name="accessControlContext">The <see cref="IAccessControlWebContext"/>.</param>
        public async Task StoreAuthenticatedPrincipalAsync(AccessControlPrincipal principal, HttpContext httpContext, IAccessControlWebContext accessControlContext)
        {
            if (!principal.IsAuthenticatePrincipal())
                throw new ArgumentException("The principal is not authenticated.", nameof(principal));

            await StorePrincipalAsync(principal, httpContext, accessControlContext);
        }

        /// <summary>
        /// Gets the stored <see cref="AccessControlPrincipal"/>.
        /// </summary>
        /// <param name="httpContext">The <see cref="HttpContext"/>.</param>
        /// <param name="accessControlContext">The <see cref="IAccessControlWebContext"/>.</param>
        /// <returns>A stored <see cref="AccessControlPrincipal"/> or <c>null</c>.</returns>
        protected abstract Task<AccessControlPrincipal?> GetStoredPrincipalAsync(HttpContext httpContext, IAccessControlWebContext accessControlContext);

        /// <summary>
        /// Store <see cref="AccessControlPrincipal"/>.
        /// </summary>
        /// <param name="principal">The <see cref="AccessControlPrincipal"/>.</param>
        /// <param name="httpContext">The <see cref="HttpContext"/>.</param>
        /// <param name="accessControlContext">The <see cref="IAccessControlWebContext"/>.</param>
        protected abstract Task StorePrincipalAsync(AccessControlPrincipal principal, HttpContext httpContext, IAccessControlWebContext accessControlContext);
    }
}
