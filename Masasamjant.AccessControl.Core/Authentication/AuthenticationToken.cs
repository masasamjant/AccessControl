using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authentication
{
    public class AuthenticationToken : IAuthored
    {
        public AuthenticationToken(AuthoredIdentity identity)
        {
            if (!identity.IsAuthenticated)
                throw new ArgumentException("The identity must represent authenticated identity.", nameof(identity));

            Identifier = Guid.NewGuid();
            Identity = identity;
        }

        public AuthenticationToken()
        { }

        [JsonInclude]
        public AuthoredIdentity Identity { get; internal set; } = new AuthoredIdentity();

        [JsonInclude]
        public Guid Identifier { get; internal set; }

        [JsonIgnore]
        public Authority Authority
        {
            get { return Identity.Authority; }
        }

        [JsonIgnore]
        public bool IsAuthenticated
        {
            get { return Identity.IsAuthenticated; }
        }
    }
}
