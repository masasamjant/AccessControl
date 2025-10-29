using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authentication token.
    /// </summary>
    public sealed class AuthenticationToken : IAuthenticationItem
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationToken"/> class.
        /// </summary>
        /// <param name="identity">The identity value.</param>
        /// <param name="authority">The authority name.</param>
        /// <param name="claims">The claims to associate with token.</param>
        public AuthenticationToken(AccessControlIdentity identity, string authority, string authenticationScheme, IEnumerable<AccessControlClaim> claims, IEnumerable<string> roles)
        {
            if (!identity.IsValid)
                throw new ArgumentException("The identity is not valid.", nameof(identity));

            if (string.IsNullOrWhiteSpace(authenticationScheme))
                throw new ArgumentNullException(nameof(authenticationScheme), "The authentication scheme is empty or only whitespace.");

            if (string.IsNullOrWhiteSpace(authority))
                throw new ArgumentNullException(nameof(authority), "The authority is empty or only whitespace.");

            Identifier = Guid.NewGuid();
            Identity = identity;
            Created = DateTimeOffset.UtcNow;
            Claims = claims.ToArray();
            Roles = roles.ToArray();
            Authority = authority;
            AuthenticationScheme = authenticationScheme;
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
        public AccessControlIdentity Identity { get; internal set; } = new AccessControlIdentity();

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
        /// Gets the roles associated with principal.
        /// </summary>
        [JsonInclude]
        public string[] Roles { get; internal set; } = [];

        /// <summary>
        /// Gets the name of authority associated with this token.
        /// </summary>
        [JsonInclude]
        public string Authority { get; internal set; } = string.Empty;

        [JsonInclude]
        public string AuthenticationScheme { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets if or not this is valid token.
        /// </summary>
        [JsonIgnore]
        public bool IsValid
        {
            get { return !Identifier.IsEmpty() && Identity.IsValid && !string.IsNullOrWhiteSpace(Authority); }
        }
    }
}
