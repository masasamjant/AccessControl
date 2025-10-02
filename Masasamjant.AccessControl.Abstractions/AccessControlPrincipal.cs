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
        private string[] roles = [];

        /// <summary>
        /// Initializes new instance of the <see cref="AccessControlPrincipal"/> class with specified identity.
        /// </summary>
        /// <param name="identity">The <see cref="AccessControlIdentity"/> of this principal.</param>
        /// <param name="authority">The <see cref="IAccessControlAuthority"/> who author this principal.</param>
        /// <param name="authenticationScheme">The authentication scheme used to authenticate identity.</param>
        public AccessControlPrincipal(AccessControlIdentity identity, IAccessControlAuthority authority, string authenticationScheme)
        {
            Identity = identity;
            
            if (identity.IsValid && identity.IsAuthenticated)
            {
                AuthenticationToken = authority.CreateAuthenticationToken(this, authenticationScheme);
                Claims = authority.GetPrincipalClaims(this).ToArray();
                Roles = authority.GetPrincipalRoles(this).ToArray();
            }
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AccessControlPrincipal"/> class that is not valid.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AccessControlPrincipal()
        { }

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
        public string[] Roles 
        {
            get { return roles.Length > 0 ? (string[])roles.Clone() : []; }
            internal set 
            {
                if (value.Length == 0)
                    roles = [];
                else
                    roles = (string[])value.Clone();
            }
        }

        #region IPrincipal

        bool IPrincipal.IsInRole(string role)
        {
            return Roles.Length > 0 && Roles.Contains(role);
        }

        IIdentity? IPrincipal.Identity => Identity;

        #endregion
    }
}
