using Masasamjant.AccessControl.Authorization;

namespace Masasamjant.AccessControl.Web.Authorization
{
    /// <summary>
    /// Access control authorization middleware.
    /// </summary>
    public class AuthorizationMiddleware
    {
        private readonly RequestDelegate next;

        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationMiddleware"/> class.
        /// </summary>
        /// <param name="next">The request delegate of next middleware.</param>
        public AuthorizationMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        /// <summary>
        /// Executes middleware.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <param name="contextProvider">The <see cref="IAuthorizationMiddlewareContextProvider"/>.</param>
        /// <returns>A task representing middleware execution.</returns>
        /// <exception cref="UnauthorizedAccessException">If request not authorized and redirect URL was not specified in context.</exception>
        public async Task InvokeAsync(HttpContext context, IAuthorizationMiddlewareContextProvider contextProvider)
        {
            var endpoint = context.GetEndpoint();
            var requiredAccessAttributes = endpoint?.Metadata.GetOrderedMetadata<RequiredAccessAttribute>() ?? [];

            // No any access attributes.
            if (requiredAccessAttributes.Count == 0)
            {
                await next(context);
                return;
            }

            var authorizationContext = contextProvider.GetAuthorizationContext();
            var accessControlPrincipal = await authorizationContext.PrincipalStore.GetAuthenticatedPrincipalAsync(context, authorizationContext);

            if (AccessControlHelper.IsAuthenticatePrincipal(accessControlPrincipal))
            {
                var accessSubject = new AccessSubject(accessControlPrincipal);
                var accessRequests = requiredAccessAttributes.Select(x => new AccessRequest(accessSubject, x.AccessObject, x.AccessType)).ToList();
                
                foreach (var accessRequest in accessRequests)
                {
                    var accessDecision = await authorizationContext.Authorizer.AuthorizeAsync(accessRequest);

                    if (accessDecision.IsValid)
                        throw new InvalidOperationException("Invalid access decision created.");

                    if (accessDecision.Result == AccessResult.Deny)
                    {
                        var accessDeniedUrl = authorizationContext.UrlProvider.GetAccessDeniesUrl(context);

                        if (string.IsNullOrWhiteSpace(accessDeniedUrl))
                            throw new UnauthorizedAccessException($"Access to {accessRequest.Object} is not authorized.");
                        else
                            context.Response.Redirect(accessDeniedUrl);
                        
                        return;
                    }
                }

                await next(context);
            }
            else
            {
                var redirectUrl = authorizationContext.UrlProvider.GetLoginUrl(context) ?? authorizationContext.UrlProvider.GetUnauthenticatedUrl(context);

                if (string.IsNullOrWhiteSpace(redirectUrl))
                    throw new UnauthorizedAccessException("Authenticate principal not found.");
                else
                    context.Response.Redirect(redirectUrl);
                return;
            }
        }
    }
}
