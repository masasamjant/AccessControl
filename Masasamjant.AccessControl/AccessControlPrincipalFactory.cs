using Masasamjant.AccessControl.Authentication;
using Masasamjant.Security.Claims;
using System.Security.Claims;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Factory class to create <see cref="AccessControlPrincipal"/> instances.
    /// </summary>
    public static class AccessControlPrincipalFactory
    {
        /// <summary>
        /// Creates <see cref="AccessControlPrincipal"/> for specified <see cref="AccessControlIdentity"/>.
        /// </summary>
        /// <param name="identity">The <see cref="AccessControlIdentity"/>.</param>
        /// <param name="authority">The <see cref="IAccessControlAuthority"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns>A <see cref="AccessControlPrincipal"/>.</returns>
        public static async Task<AccessControlPrincipal> CreateAsync(AccessControlIdentity identity, IAccessControlAuthority authority, string authenticationScheme)
        {
            if (identity.Authority != authority.Name)
                throw new ArgumentException("The authority is not same.", nameof(identity));

            if (!authority.IsSupportedAuthentication(authenticationScheme))
                throw new ArgumentException("The authentication scheme is not supported by authority.", nameof(authenticationScheme));

            var claimList = new List<AccessControlClaim>
            {
                new AccessControlClaim(AccessControlClaims.IdentityName, identity.Name, authority.Name),
                new AccessControlClaim(AccessControlClaims.Authority, identity.Authority, authority.Name)
            };

            if (identity.IsValid && identity.IsAuthenticated)
            {
                claimList.Add(new AccessControlClaim(AccessControlClaims.AuthenticationScheme, authenticationScheme, authority.Name));
                var principal = new AccessControlPrincipal(identity, claimList);

                // Get custom claims skip once using reserved claim key.
                var claims = (await authority.GetPrincipalClaimsAsync(principal)).Where(x => !x.IsEmpty && !AccessControlClaims.IsReservedClaim(x.Key)).ToArray();

                foreach (var claim in claims)
                    claimList.Add(claim);

                // Get principal roles.
                var roles = (await authority.GetPrincipalRolesAsync(principal)).Where(x => !x.IsEmpty).ToArray();
                //principal.Roles = roles;

                // Build roles claim.
                var roleNames = roles.Select(x => x.FullName).ToArray();

                var separator = CharHelper.GetCommonSeparator(roleNames);

                if (!separator.HasValue)
                    separator = CharHelper.GetSeparator(roleNames, ['#', '&', '^', '*', '~', '@']);

                if (!separator.HasValue)
                    throw new InvalidOperationException("Could not resolve separator character for roles.");

                var rolesClaim = roleNames.Length > 0 ? separator.Value + string.Join(separator.Value, roleNames) : string.Empty;

                if (rolesClaim.Length > 0)
                    claimList.Add(new AccessControlClaim(AccessControlClaims.Roles, rolesClaim, authority.Name));

                // Creata authentication token and claim.
                principal = new AccessControlPrincipal(identity, claimList, roles);
                var authenticationToken = await authority.CreateAuthenticationTokenAsync(principal, authenticationScheme);
                return new AccessControlPrincipal(principal, authenticationToken);
            }
            else
            {
                return new AccessControlPrincipal(identity, claimList);
            }
        }

        /// <summary>
        /// Creates <see cref="AccessControlPrincipal"/> from specified <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="claimsPrincipal">The <see cref="ClaimsPrincipal"/>.</param>
        /// <returns>A <see cref="AccessControlPrincipal"/> or <c>null</c>, if <paramref name="claimsPrincipal"/> is <c>null</c>.</returns>
        public static async Task<AccessControlPrincipal?> CreateAsync(ClaimsPrincipal? claimsPrincipal, IAuthenticationTokenAuthenticator authenticator)
        {
            if (claimsPrincipal == null)
                return null;

            var nameClaim = claimsPrincipal.GetFirstClaim(AccessControlClaims.IdentityName);
            var authorityClaim = claimsPrincipal.GetFirstClaim(AccessControlClaims.Authority);

            // If required claims are not present or authority mismatch, then return invalid principal.
            if (nameClaim == null || authorityClaim == null || authenticator.Authority.Name != authorityClaim.Value)
                return new AccessControlPrincipal();

            var authenticationTokenClaim = claimsPrincipal.GetFirstClaim(AccessControlClaims.AuthenticationToken);
            var authenticationSchemeClaim = claimsPrincipal.GetFirstClaim(AccessControlClaims.AuthenticationScheme);

            // If authentication token claim and authentication scheme claim are present.
            if (authenticationTokenClaim != null && authenticationSchemeClaim != null)
            {
                // Authenticate token from claims.
                var authenticationToken = authenticationTokenClaim.Value;
                var response = await authenticator.AuthenticateTokenAsync(authenticationToken);


                if (response.Result != AuthenticationResult.Authenticated)
                {
                    var identity = new AccessControlIdentity(nameClaim.Value, authenticator.Authority.Name);
                    return new AccessControlPrincipal(identity);
                }
                else
                {
                    var identity = new AccessControlIdentity(nameClaim.Value, true, authenticationSchemeClaim.Value, authenticator.Authority.Name);

                    // Build roles.
                    var rolesClaim = claimsPrincipal.GetFirstClaim(AccessControlClaims.Roles);

                    var roles = new List<AccessControlRole>();

                    if (rolesClaim != null && !string.IsNullOrWhiteSpace(rolesClaim.Value))
                    {
                        var separator = rolesClaim.Value[0];
                        var values = rolesClaim.Value.Remove(0, 1).Split(separator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

                        foreach (var value in values)
                        {
                            var parts = value.Split(AccessControlRole.NameSeparator);

                            if (parts.Length == 2)
                                roles.Add(new AccessControlRole(parts[1], parts[0]));
                        }
                    }

                    // Build claims
                    var claims = new List<AccessControlClaim>(claimsPrincipal.Claims.Count());

                    foreach (var claim in claimsPrincipal.Claims)
                    {
                        claims.Add(new AccessControlClaim(claim.Type, claim.Value, identity.Authority));
                    }

                    var principal = new AccessControlPrincipal(identity, claims, roles);
                    return new AccessControlPrincipal(principal, authenticationTokenClaim.Value);
                }

            }
            else
            {
                var identity = new AccessControlIdentity(nameClaim.Value, authenticator.Authority.Name);
                return new AccessControlPrincipal(identity);
            }
        }
    }
}
