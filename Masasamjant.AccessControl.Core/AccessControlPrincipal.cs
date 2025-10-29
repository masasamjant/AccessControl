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

        public AccessControlPrincipal(AccessControlIdentity identity, IEnumerable<AccessControlClaim>? claims = null, IEnumerable<AccessControlRole>? roles = null)
        {
            Identity = identity;
            Authority = identity.Authority;
            if (claims != null)
                this.claims.AddRange(claims);
            if (roles != null)
                this.roles.AddRange(roles);
        }

        public AccessControlPrincipal(AccessControlPrincipal principal, string authenticationToken)
        {
            Identity = principal.Identity;
            Authority = principal.Authority;
            claims.AddRange(principal.Claims);
            claims.Add(new AccessControlClaim(AccessControlClaims.AuthenticationToken, authenticationToken, Authority));
            roles.AddRange(principal.Roles);
            AuthenticationToken = authenticationToken;
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

        #region IPrincipal

        bool IPrincipal.IsInRole(string role)
        {
            return Roles.Length > 0 && Roles.Any(x => x.FullName == role);
        }

        IIdentity? IPrincipal.Identity => Identity;

        #endregion
    }
}
