using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl
{
    public class AuthoredPrincipal : ClaimsPrincipal, IAuthored
    {
        public AuthoredPrincipal(AuthoredIdentity identity)
            : base(identity)
        {
            Authority = identity.Authority;
            Identity = identity;
        }

        public AuthoredPrincipal() 
        { }

        [JsonInclude]
        public Authority Authority { get; internal set; } = new Authority();

        [JsonInclude]
        public new AuthoredIdentity Identity { get; internal set; } = new AuthoredIdentity();

        public override void AddIdentities(IEnumerable<ClaimsIdentity> identities)
        {
            throw new NotSupportedException("Adding identities is not supported.");
        }

        public override void AddIdentity(ClaimsIdentity identity)
        {
            throw new NotSupportedException("Adding identity is not supported.");
        }

        public override bool IsInRole(string role)
        {
            return Identity.Roles.Any(x => x.Name == role);
        }
    }
}
