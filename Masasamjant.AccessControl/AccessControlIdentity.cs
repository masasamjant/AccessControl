using System.Security.Principal;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl
{
    public sealed class AccessControlIdentity : IIdentity
    {
        public AccessControlIdentity(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The name is empty or only whitespace.");

            Name = name;
            AuthenticationType = null;
            IsAuthenticated = false;
        }

        public AccessControlIdentity() 
        { }

        [JsonInclude]
        public string? AuthenticationType { get; internal set; }

        [JsonInclude]
        public bool IsAuthenticated { get; internal set; }

        [JsonInclude]
        public string Name { get; internal set; } = string.Empty;

        [JsonInclude]
        public string? AuthenticationToken { get; internal set; }

        [JsonIgnore]
        public bool IsValid
        {
            get { return !string.IsNullOrWhiteSpace(Name); }
        }
    }
}
