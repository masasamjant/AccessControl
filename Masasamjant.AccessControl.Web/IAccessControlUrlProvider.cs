namespace Masasamjant.AccessControl.Web
{
    /// <summary>
    /// Represents provider of application URLs related to access control. 
    /// </summary>
    public interface IAccessControlUrlProvider
    {
        /// <summary>
        /// Gets the URL to resource where request is redirected on login.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <returns>A login URL or <c>null</c>.</returns>
        string? GetLoginUrl(HttpContext context);

        /// <summary>
        /// Gets the URL to resource where request is redirected on unauthorized access.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <returns>A access denied URL or <c>null</c>.</returns>
        string? GetAccessDeniesUrl(HttpContext context);

        /// <summary>
        /// Gets the URL to resource where request is redirected when unauthenticated.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <returns>A unauthenticated URL or <c>null</c>.</returns>
        /// <remarks>This should be alternative to login URL if that is not used.</remarks>
        string? GetUnauthenticatedUrl(HttpContext context);
    }
}
