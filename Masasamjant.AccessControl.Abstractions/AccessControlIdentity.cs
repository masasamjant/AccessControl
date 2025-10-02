using System.Security.Principal;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents identity of <see cref="AccessControlPrincipal"/>.
    /// </summary>
    public class AccessControlIdentity : IIdentity
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessControlIdentity"/> class.
        /// </summary>
        /// <param name="name">The unique name of identity.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="name"/> is empty or only whitespace.</exception>
        public AccessControlIdentity(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The name is empty or only whitespace.");

            Name = name;
            AuthenticationType = null;
            IsAuthenticated = false;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AccessControlIdentity"/> class 
        /// to create invalid identity.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AccessControlIdentity() 
        { }

        protected AccessControlIdentity(string name, bool authenticated, string authenticationScheme)
            : this(name)
        {
            IsAuthenticated = authenticated;
            AuthenticationType = authenticationScheme;
        }

        /// <summary>
        /// Gets the authentication type.
        /// </summary>
        [JsonInclude]
        public string? AuthenticationType { get; internal set; }

        /// <summary>
        /// Gets if or not authenticated.
        /// </summary>
        [JsonInclude]
        public bool IsAuthenticated { get; internal set; }

        /// <summary>
        /// Gets the unique name of identity.
        /// </summary>
        [JsonInclude]
        public string Name { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets if or not this identity is valid.
        /// </summary>
        [JsonIgnore]
        public bool IsValid
        {
            get { return !string.IsNullOrWhiteSpace(Name); }
        }
    }
}
