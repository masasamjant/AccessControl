using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents abstract authentication response.
    /// </summary>
    public abstract class AuthenticationResponse : IAuthored
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationResponse"/> class with specified authority.
        /// </summary>
        /// <param name="authority">The authority.</param>
        protected AuthenticationResponse(Authority authority)
        {
            Authority = authority;
            Identifier = Guid.NewGuid();
            Created = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AuthenticationResponse"/> class that represents empty response.
        /// </summary>
        protected AuthenticationResponse()
        { }

        /// <summary>
        /// Gets the unique identifier.
        /// </summary>
        [JsonInclude]
        public Guid Identifier { get; internal set; }

        /// <summary>
        /// Gets the authority.
        /// </summary>
        [JsonInclude]
        public Authority Authority { get; internal set; } = new Authority();

        /// <summary>
        /// Gets the UTC date and time when response was created.
        /// </summary>
        [JsonInclude]
        public DateTimeOffset Created { get; internal set; }
    }
}
