using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl
{
    public class AuthoredRole : IAuthored
    {
        public AuthoredRole(Authority authority, string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The name of role is empty or only whitespace.");

            Authority = authority;
            Name = name;
        }

        public AuthoredRole()
        { }

        [JsonInclude]
        public Authority Authority { get; internal set; } = new Authority();

        [JsonInclude]
        public string Name { get; internal set; } = string.Empty;
    }
}
