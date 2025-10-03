using System.Security.Principal;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents access control principal.
    /// </summary>
    public sealed class AccessControlPrincipal : IPrincipal
    {
        private AccessControlClaim[] claims = [];
        private AccessControlRole[] roles = [];

        /// <summary>
        /// Initializes new default instance of the <see cref="AccessControlPrincipal"/> class that is not valid.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AccessControlPrincipal()
        { }

        private AccessControlPrincipal(AccessControlIdentity identity)
        {
            Identity = identity;
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
            get { return claims.Length > 0 ? (AccessControlClaim[])claims.Clone() : []; }
            internal set 
            {
                if (value.Length == 0)
                    claims = [];
                else
                    claims = (AccessControlClaim[])value.Clone();
            }
        }

        /// <summary>
        /// Gets the names of roles assigned to this principal.
        /// </summary>
        [JsonInclude]
        public AccessControlRole[] Roles 
        {
            get { return roles.Length > 0 ? (AccessControlRole[])roles.Clone() : []; }
            internal set 
            {
                if (value.Length == 0)
                    roles = [];
                else
                    roles = (AccessControlRole[])value.Clone();
            }
        }

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

            var principal = new AccessControlPrincipal(identity);
            if (identity.IsValid && identity.IsAuthenticated)
            {
                principal.Claims = (await authority.GetPrincipalClaimsAsync(principal)).Where(x => !x.IsEmpty).ToArray();
                principal.Roles = (await authority.GetPrincipalRolesAsync(principal)).Where(x => !x.IsEmpty).ToArray();
                principal.AuthenticationToken = await authority.CreateAuthenticationTokenAsync(principal, authenticationScheme);
            }

            return principal;
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
