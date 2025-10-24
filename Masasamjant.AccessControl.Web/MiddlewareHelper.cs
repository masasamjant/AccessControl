using Masasamjant.AccessControl.Web.Authentication;
using Masasamjant.AccessControl.Web.Authorization;

namespace Masasamjant.AccessControl.Web
{
    /// <summary>
    /// Provides helper method to register required middlewares.
    /// </summary>
    public static class MiddlewareHelper
    {
        /// <summary>
        /// Register <see cref="AuthenticationMiddleware"/> and <see cref="AuthorizationMiddleware"/> middlewares 
        /// that perform authentication and authorization.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/>.</param>
        /// <returns>A <see cref="IApplicationBuilder"/>.</returns>
        public static IApplicationBuilder UseAccessControl(this IApplicationBuilder app) 
        {
            app.UseMiddleware<AuthenticationMiddleware>();
            app.UseMiddleware<AuthorizationMiddleware>();
            return app;
        }
    }
}
