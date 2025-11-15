using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authentication token.
    /// </summary>
    public sealed class AuthenticationToken : IAuthored
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationToken"/> class that represents an authenticated token.
        /// </summary>
        /// <param name="identity">The authenticated identity.</param>
        /// <exception cref="ArgumentException">If <paramref name="identity"/> does not represent authenticated identity.</exception>
        public AuthenticationToken(AuthoredIdentity identity)
        {
            if (!identity.IsAuthenticated)
                throw new ArgumentException("The identity must represent authenticated identity.", nameof(identity));

            Identifier = Guid.NewGuid();
            Identity = identity;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AuthenticationToken"/> class that represents an unauthenticated token.
        /// </summary>
        public AuthenticationToken()
        { }

        /// <summary>
        /// Gets the identity associated with the authentication token.
        /// </summary>
        [JsonInclude]
        public AuthoredIdentity Identity { get; internal set; } = new AuthoredIdentity();

        /// <summary>
        /// Gets the unique identifier.
        /// </summary>
        [JsonInclude]
        public Guid Identifier { get; internal set; }

        /// <summary>
        /// Gets the authority.
        /// </summary>
        [JsonIgnore]
        public Authority Authority
        {
            get { return Identity.Authority; }
        }

        /// <summary>
        /// Gets a value indicating whether the token represents an authenticated identity.
        /// </summary>
        [JsonIgnore]
        public bool IsAuthenticated
        {
            get { return Identity.IsAuthenticated; }
        }
    }
}
