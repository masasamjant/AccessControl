using Masasamjant.AccessControl.Authentication;
using Masasamjant.Security.Claims;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents access control principal.
    /// </summary>
    public sealed class AccessControlPrincipal : IPrincipal
    {
        private List<AccessControlClaim> claims = [];
        private List<AccessControlRole> roles = [];

        /// <summary>
        /// Initializes new default instance of the <see cref="AccessControlPrincipal"/> class that is not valid.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AccessControlPrincipal()
        { }

        private AccessControlPrincipal(AccessControlIdentity identity, IAccessControlAuthority authority)
        {
            Identity = identity;
            Authority = authority.Name;
        }

        /// <summary>
        /// Gets the <see cref="AccessControlIdentity"/> of this principal.
        /// </summary>
        [JsonInclude]
        public AccessControlIdentity Identity { get; internal set; } = new AccessControlIdentity();

        /// <summary>
        /// Gets the authentication token if represents authenticated principal.
        /// </summary>
        [JsonInclude]
        public string? AuthenticationToken { get; internal set; }

        /// <summary>
        /// Gets the claims of this principal.
        /// </summary>
        [JsonInclude]
        public AccessControlClaim[] Claims
        {
            get { return claims.Count > 0 ? [.. claims] : []; }
            internal set 
            {
                if (value.Length == 0)
                    claims = [];
                else
                    claims = [.. value];
            }
        }

        /// <summary>
        /// Gets the names of roles assigned to this principal.
        /// </summary>
        [JsonInclude]
        public AccessControlRole[] Roles 
        {
            get { return roles.Count > 0 ? [.. roles] : []; }
            internal set 
            {
                if (value.Length == 0)
                    roles = [];
                else
                    roles = [.. value];
            }
        }

        /// <summary>
        /// Gets the name of authority.
        /// </summary>
        [JsonInclude]
        public string Authority { get; internal set; } = string.Empty;

        /// <summary>
        /// Creates <see cref="AccessControlPrincipal"/> for specified <see cref="AccessControlIdentity"/>.
        /// </summary>
        /// <param name="identity">The <see cref="AccessControlIdentity"/>.</param>
        /// <param name="authority">The <see cref="IAccessControlAuthority"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns>A <see cref="AccessControlPrincipal"/>.</returns>
        public static async Task<AccessControlPrincipal> CreateAsync(AccessControlIdentity identity, IAccessControlAuthority authority, string authenticationScheme)
        {
            if (!authority.IsSupportedAuthentication(authenticationScheme))
                throw new ArgumentException("The authentication scheme is not supported by authority.", nameof(authenticationScheme));

            var principal = new AccessControlPrincipal(identity, authority);

            principal.claims.Add(new AccessControlClaim(AccessControlClaims.IdentityName, principal.Identity.Name, authority));
            principal.claims.Add(new AccessControlClaim(AccessControlClaims.Authority, principal.Authority, authority));

            if (identity.IsValid && identity.IsAuthenticated)
            {
                principal.claims.Add(new AccessControlClaim(AccessControlClaims.AuthenticationScheme, authenticationScheme, authority));
                
                // Get custom claims skip once using reserved claim key.
                var claims = (await authority.GetPrincipalClaimsAsync(principal)).Where(x => !x.IsEmpty && !AccessControlClaims.IsReservedClaim(x.Key)).ToArray();

                foreach (var claim in claims)
                    principal.claims.Add(claim);
                
                // Get principal roles.
                var roles = (await authority.GetPrincipalRolesAsync(principal)).Where(x => !x.IsEmpty).ToArray();
                principal.Roles = roles;

                // Build roles claim.
                var roleNames = roles.Select(x => x.FullName).ToArray();

                var separator = CharHelper.GetCommonSeparator(roleNames);

                if (!separator.HasValue)
                    separator = CharHelper.GetSeparator(roleNames, ['#', '&', '^', '*', '~', '@']);

                if (!separator.HasValue)
                    throw new InvalidOperationException("Could not resolve separator character for roles.");

                var rolesClaim = roleNames.Length > 0 ? separator.Value + string.Join(separator.Value, roleNames) : string.Empty;

                if (rolesClaim.Length > 0)
                    principal.claims.Add(new AccessControlClaim(AccessControlClaims.Roles, rolesClaim, authority));

                // Creata authentication token and claim.
                principal.AuthenticationToken = await authority.CreateAuthenticationTokenAsync(principal, authenticationScheme);
                principal.claims.Add(new AccessControlClaim(AccessControlClaims.AuthenticationToken, principal.AuthenticationToken, authority));
            }

            return principal;
        }

        /// <summary>
        /// Creates claims principal based on this, if represents valid authenticated principal.
        /// </summary>
        /// <returns>A <see cref="ClaimsPrincipal"/> if represents valid and authenticated principal; <c>null</c> otherwise.</returns>
        public ClaimsPrincipal? CreateClaimsPrincipal()
        {
            if (AccessControlHelper.IsAuthenticatePrincipal(this))
            {
                var claims = new List<Claim>();

                foreach (var claim in Claims)
                {
                    if (claim.IsEmpty)
                        continue;

                    claims.Add(new Claim(claim.Key, claim.Value, null, claim.Authority));
                }

                var claimsIdentity = new ClaimsIdentity(claims, Identity.AuthenticationType);
                return new ClaimsPrincipal(claimsIdentity);
            }

            return null;
        }

        /// <summary>
        /// Creates <see cref="AccessControlPrincipal"/> from specified <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="claimsPrincipal">The <see cref="ClaimsPrincipal"/>.</param>
        /// <returns>A <see cref="AccessControlPrincipal"/> or <c>null</c>, if <paramref name="claimsPrincipal"/> is <c>null</c>.</returns>
        public static async Task<AccessControlPrincipal?> CreateFromAsync(ClaimsPrincipal? claimsPrincipal, IAuthenticationTokenAuthenticator authenticator)
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
                    var identity = new AccessControlIdentity(nameClaim.Value);

                    return new AccessControlPrincipal()
                    {
                        Identity = identity,
                        Authority = authorityClaim.Value
                    };
                }
                else
                {
                    var identity = new AccessControlIdentity(nameClaim.Value, true, authenticationSchemeClaim.Value);

                    var principal = new AccessControlPrincipal()
                    {
                        Identity = identity,
                        AuthenticationToken = authenticationTokenClaim.Value,
                        Authority = authorityClaim.Value,
                    };

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

                    principal.Roles = [.. roles];

                    // Build claims
                    var claims = new List<AccessControlClaim>(claimsPrincipal.Claims.Count());

                    foreach (var claim in claimsPrincipal.Claims)
                    {
                        claims.Add(new AccessControlClaim()
                        {
                            Key = claim.Type,
                            Value = claim.Value,
                            Authority = principal.Authority
                        });
                    }

                    principal.Claims = [.. claims];

                    return principal;
                }

            }
            else
            {
                var identity = new AccessControlIdentity(nameClaim.Value);
                
                return new AccessControlPrincipal()
                {
                    Identity = identity,
                    Authority = authorityClaim.Value
                };
            }
        }

        #region IPrincipal

        bool IPrincipal.IsInRole(string role)
        {
            return Roles.Length > 0 && Roles.Any(x => x.FullName == role);
        }

        IIdentity? IPrincipal.Identity => Identity;

        #endregion
    }
}
