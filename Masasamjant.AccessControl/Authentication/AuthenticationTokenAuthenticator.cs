using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authentication
{
    public sealed class AuthenticationTokenAuthenticator : IAuthenticationTokenAuthenticator
    {
        public AuthenticationTokenAuthenticator(AccessControlAuthority authority)
            : this(authority, new DefaultAuthenticationItemValidator())
        { }

        public AuthenticationTokenAuthenticator(AccessControlAuthority authority, IAuthenticationItemValidator itemValidator)
        {
            Authority = authority;
            ItemValidator = itemValidator;
        }

        private IAuthenticationItemValidator ItemValidator { get; }

        private AccessControlAuthority Authority { get; }

        /// <summary>
        /// Authenticates specified <see cref="AuthenticationToken"/>.
        /// </summary>
        /// <param name="authenticationToken">The authentication token string from <see cref="AuthenticationToken.Identity"/>.</param>
        /// <returns>A <see cref="AuthenticationResultResponse"/>.</returns>
        /// <exception cref="AuthenticationException">
        /// If <paramref name="token"/> is not valid.
        /// -or-
        /// If authentication process fails.
        /// </exception>
        public AuthenticationResultResponse AuthenticateToken(string authenticationToken)
        {
            var token = Authority.CreateAuthenticationToken(authenticationToken);

            if (!token.IsValid)
                throw new AuthenticationException("Authentication token is not valid.", token);

            try
            {
                var validation = ItemValidator.IsValidToken(token);

                if (!validation.IsValid)
                    throw new AuthenticationException(string.IsNullOrWhiteSpace(validation.UnvalidReason) ? "Authentication token is not valid." : validation.UnvalidReason, token);

                if (!token.Identity.IsAuthenticated)
                    return new AuthenticationResultResponse(null, Authority.Name);

                if (!Authority.IsAuthoring(token.Identity))
                    return new AuthenticationResultResponse(null, Authority.Name);

                var principal = new AccessControlPrincipal(token.Identity);
                principal.SetClaims(Authority);
                principal.SetRoles(Authority);
                principal.CreateAuthenticationToken(Authority, token.AuthenticationScheme);

                return new AuthenticationResultResponse(principal, Authority.Name);
            }
            catch (Exception exception)
            {
                if (exception is AuthenticationException)
                    throw;
                else
                    throw new AuthenticationException("Could not authenticate token. See inner exception.", token, exception);
            }
        }
    }
}
