using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authentication token.
    /// </summary>
    public class AuthenticationToken : IAuthenticationItem
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationToken"/> class.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="claims">The claims to associate with token.</param>
        public AuthenticationToken(string value, IEnumerable<AccessControlClaim> claims)
        {
            Identifier = Guid.NewGuid();
            Value = value;
            Created = DateTimeOffset.UtcNow;
            Claims = claims.ToArray();
        }

        /// <summary>
        /// Initializes new invalid instance of the <see cref="AuthenticationToken"/> class. This should be used 
        /// when valid token cannot be constructed.
        /// </summary>
        public AuthenticationToken() 
        { }

        /// <summary>
        /// Gets the unique identifier of this token.
        /// </summary>
        [JsonInclude]
        public Guid Identifier { get; internal set; }

        /// <summary>
        /// Gets the token value.
        /// </summary>
        [JsonInclude]
        public string Value { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets the UTC date and time when token was created.
        /// </summary>
        [JsonInclude]
        public DateTimeOffset Created { get; internal set; }

        /// <summary>
        /// Gets the claims associated with token.
        /// </summary>
        [JsonInclude]
        public AccessControlClaim[] Claims { get; internal set; } = [];

        /// <summary>
        /// Gets the UTC date and time when token was refreshed.
        /// </summary>
        [JsonInclude]
        public DateTimeOffset? Refreshed { get; internal set; }

        /// <summary>
        /// Gets if or not this is valid token.
        /// </summary>
        [JsonIgnore]
        public bool IsValid
        {
            get { return !Identifier.IsEmpty() && !string.IsNullOrWhiteSpace(Value); }
        }

        /// <summary>
        /// Updates <see cref="Refreshed"/> value.
        /// </summary>
        /// <exception cref="InvalidOperationException">If <see cref="IsValid"/> is <c>false</c>.</exception>
        protected internal void Refresh()
        {
            if (!IsValid)
                throw new InvalidOperationException("Authentication token is not valid.");

            Refreshed = DateTimeOffset.UtcNow;
        }
    }
}
