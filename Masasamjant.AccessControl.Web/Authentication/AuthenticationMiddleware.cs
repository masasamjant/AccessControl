using Masasamjant.AccessControl.Authentication;
using Masasamjant.Security.Claims;

namespace Masasamjant.AccessControl.Web.Authentication
{
    /// <summary>
    /// Access control authentication middleware.
    /// </summary>
    public sealed class AuthenticationMiddleware
    {
        private readonly RequestDelegate next;

        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationMiddleware"/> class.
        /// </summary>
        /// <param name="next">The request delegate of next middleware.</param>
        public AuthenticationMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        /// <summary>
        /// Executes middleware.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <param name="contextProvider">The <see cref="IAuthenticationMiddlewareContextProvider"/>.</param>
        /// <returns>A task representing middleware execution.</returns>
        /// <exception cref="UnauthorizedAccessException">If request not authenticated and redirect URL was not specified in context.</exception>
        public async Task InvokeAsync(HttpContext context, IAuthenticationMiddlewareContextProvider contextProvider) 
        {
            var endpoint = context.GetEndpoint();
            var authenticationAttributes = endpoint?.Metadata.GetOrderedMetadata<AccessControlAuthenticationAttribute>() ?? [];
            var authenticationAttribute = authenticationAttributes.Count == 1 ? authenticationAttributes[0] : null;

            if (authenticationAttribute != null)
            {
                bool authenticated = false;

                var authenticationContext = contextProvider.GetAuthenticationContext();

                if (context.User.Identity != null &&
                    context.User.Identity.IsAuthenticated)
                {
                    var claim = context.User.GetFirstClaim(AccessControlClaims.AuthenticationToken);

                    if (claim != null)
                    {
                        var authenticationToken = claim.Value;

                        if (!string.IsNullOrWhiteSpace(authenticationToken))
                        {
                            var authenticationResponse = await authenticationContext.Authenticator.AuthenticateTokenAsync(authenticationToken);

                            if (authenticationResponse.IsValid && authenticationResponse.Result == AuthenticationResult.Authenticated && authenticationResponse.Principal.IsAuthenticatePrincipal())
                            {
                                await authenticationContext.PrincipalStore.StoreAuthenticatedPrincipalAsync(authenticationResponse.Principal, context, authenticationContext);
                                authenticated = true;
                            }
                        }
                    }
                }

                // Not authenticated redirect to log out or unauthenticated url or if neither specified then throw exception.
                if (!authenticated)
                {
                    var redirectUrl = authenticationAttribute.RedirectUrl ?? 
                        authenticationContext.UrlProvider.GetLoginUrl(context) ?? 
                        authenticationContext.UrlProvider.GetUnauthenticatedUrl(context);
                    
                    if (string.IsNullOrWhiteSpace(redirectUrl))
                        throw new UnauthorizedAccessException("Request is not authenticated.");
                    else
                        context.Response.Redirect(redirectUrl);
                    
                    return;
                }
            }
           
            await next(context);
        }
    }
}
