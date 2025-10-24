namespace Masasamjant.AccessControl.Web.Authentication
{
    /// <summary>
    /// Represents provider of <see cref="AuthenticationMiddlewareContext"/>.
    /// </summary>
    public interface IAuthenticationMiddlewareContextProvider
    {
        /// <summary>
        /// Gets the <see cref="AuthenticationMiddlewareContext"/> for <see cref="AuthenticationMiddleware"/>.
        /// </summary>
        /// <returns>A <see cref="AuthenticationMiddlewareContext"/>.</returns>
        AuthenticationMiddlewareContext GetAuthenticationContext();
    }
}
