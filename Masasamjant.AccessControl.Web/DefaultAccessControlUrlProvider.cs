
namespace Masasamjant.AccessControl.Web
{
    /// <summary>
    /// Represents default implementation of <see cref="IAccessControlUrlProvider"/> interface.
    /// </summary>
    public class DefaultAccessControlUrlProvider : IAccessControlUrlProvider
    {
        private readonly string? accessDeniedUrl;
        private readonly string? loginUrl;
        private readonly string? unauthenticatedUrl;

        /// <summary>
        /// Initializes new default instance of the <see cref="DefaultAccessControlUrlProvider"/> class that returns <c>null</c> to each URL.
        /// </summary>
        public DefaultAccessControlUrlProvider()
        { }

        /// <summary>
        /// Initializes new instance of the <see cref="DefaultAccessControlUrlProvider"/> class.
        /// </summary>
        /// <param name="accessDeniedUrl">The access denied URL or <c>null</c>.</param>
        /// <param name="loginUrl">The login URL or <c>null</c>.</param>
        /// <param name="unauthenticatedUrl">The unauthenticated URL or <c>null</c>.</param>
        public DefaultAccessControlUrlProvider(string? accessDeniedUrl, string? loginUrl, string? unauthenticatedUrl)
        {
            this.accessDeniedUrl = string.IsNullOrWhiteSpace(accessDeniedUrl) ? null : accessDeniedUrl;
            this.loginUrl = string.IsNullOrWhiteSpace(loginUrl) ? null : loginUrl;
            this.unauthenticatedUrl = string.IsNullOrWhiteSpace(unauthenticatedUrl) ? null : unauthenticatedUrl;
        }

        /// <summary>
        /// Gets the URL to resource where request is redirected on unauthorized access.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <returns>A access denied URL or <c>null</c>.</returns>
        public virtual string? GetAccessDeniesUrl(HttpContext context)
        {
            return accessDeniedUrl;
        }

        /// <summary>
        /// Gets the URL to resource where request is redirected on login.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <returns>A login URL or <c>null</c>.</returns>
        public virtual string? GetLoginUrl(HttpContext context)
        {
            return loginUrl;
        }

        /// <summary>
        /// Gets the URL to resource where request is redirected when unauthenticated.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <returns>A unauthenticated URL or <c>null</c>.</returns>
        /// <remarks>This should be alternative to login URL if that is not used.</remarks>
        public virtual string? GetUnauthenticatedUrl(HttpContext context)
        {
            return unauthenticatedUrl;
        }
    }
}
