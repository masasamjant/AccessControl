namespace Masasamjant.AccessControl.Web.Authorization
{
    /// <summary>
    /// Represents provider of <see cref="AuthorizationMiddlewareContext"/>.
    /// </summary>
    public interface IAuthorizationMiddlewareContextProvider
    {
        /// <summary>
        /// Gets the <see cref="AuthorizationMiddlewareContext"/> for <see cref="AuthorizationMiddleware"/>.
        /// </summary>
        /// <returns>A <see cref="AuthorizationMiddlewareContext"/>.</returns>
        AuthorizationMiddlewareContext GetAuthorizationContext();
    }
}
