using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl
{
    public class AccessControlClaim
    {
        public AccessControlClaim(string key, string value)
        {
            Key = key;
            Value = value;
        }

        internal AccessControlClaim(string key, string value, string authority)
            : this(key, value)
        { 
            Authority = authority;
        }

        public AccessControlClaim() 
        { }

        [JsonInclude]
        public string Key { get; internal set; } = string.Empty;

        [JsonInclude]
        public string Value { get; internal set; } = string.Empty;

        [JsonInclude]
        public string Authority { get; internal set; } = string.Empty;
    }
}
