using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents abstract authentication response.
    /// </summary>
    public abstract class AuthenticationResponse : IAuthenticationItem
    {
        /// <summary>
        /// Gets the unique identifier.
        /// </summary>
        [JsonInclude]
        public Guid Identifier { get; internal set; }

        /// <summary>
        /// Gets the UTC date and time when created.
        /// </summary>
        [JsonInclude]
        public DateTimeOffset Created { get; internal set; }

        /// <summary>
        /// Gets if or not is valid.
        /// </summary>
        [JsonIgnore]
        public abstract bool IsValid { get; } 
    }
}
