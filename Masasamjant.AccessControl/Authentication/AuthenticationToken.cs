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
        /// <param name="identity">The identity value.</param>
        /// <param name="authority">The authority name.</param>
        /// <param name="claims">The claims to associate with token.</param>
        internal AuthenticationToken(string identity, string authority, IEnumerable<AccessControlClaim> claims)
        {
            Identifier = Guid.NewGuid();
            Identity = identity;
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
        public string Identity { get; internal set; } = string.Empty;

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
        /// Gets the name of authority associated with this token.
        /// </summary>
        [JsonInclude]
        public string Authority { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets if or not this is valid token.
        /// </summary>
        [JsonIgnore]
        public bool IsValid
        {
            get { return !Identifier.IsEmpty() && !string.IsNullOrWhiteSpace(Identity); }
        }
    }
}
