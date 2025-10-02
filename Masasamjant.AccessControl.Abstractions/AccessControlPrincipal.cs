using Masasamjant.AccessControl.Authentication;
using System.Security.Principal;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl
{
    public sealed class AccessControlPrincipal : IPrincipal
    {
        private AccessControlClaim[] claims = [];
        private string[] roles = [];

        public AccessControlPrincipal(AccessControlIdentity identity)
        {
            Identity = identity;
        }

        public AccessControlPrincipal()
        { }

        [JsonInclude]
        public AccessControlIdentity Identity { get; internal set; } = new AccessControlIdentity();

        [JsonInclude]
        public string? AuthenticationToken { get; internal set; }

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

        public void SetClaims(IAccessControlAuthority authority)
        {
            if (Identity.IsValid && Identity.IsAuthenticated)
                Claims = authority.GetPrincipalClaims(this).ToArray();
        }

        public void SetRoles(IAccessControlAuthority authority)
        {
            if (Identity.IsValid && Identity.IsAuthenticated)
                Roles = authority.GetPrincipalRoles(this).ToArray();
        }

        public void CreateAuthenticationToken(IAccessControlAuthority authority, string authenticationScheme)
        {
            if (Identity.IsValid && Identity.IsAuthenticated)
                AuthenticationToken = authority.CreateAuthenticationToken(this, authenticationScheme);
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
