using System.Security.Principal;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl
{
    public sealed class AccessControlPrincipal : IPrincipal
    {
        internal AccessControlPrincipal(AccessControlIdentity identity)
        {
            Identity = identity;
        }

        public AccessControlPrincipal()
        { }

        [JsonInclude]
        public AccessControlIdentity Identity { get; internal set; } = new AccessControlIdentity();

        [JsonIgnore]
        public string? AuthenticationToken
        {
            get { return Identity.AuthenticationToken; }
        }

        [JsonInclude]
        public AccessControlClaim[] Claims { get; internal set; } = [];

        [JsonInclude]
        public string[] Roles { get; internal set; } = [];

        bool IPrincipal.IsInRole(string role)
        {
            return Roles.Length > 0 && Roles.Contains(role);
        }

        IIdentity? IPrincipal.Identity => Identity;
    }
}
