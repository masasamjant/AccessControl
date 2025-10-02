using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents response to <see cref="AuthenticationRequest"/>.
    /// </summary>
    public sealed class AuthenticationRequestResponse : AuthenticationResponse
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationRequestResponse"/> for specified <see cref="AuthenticationRequest"/>.
        /// </summary>
        /// <param name="request">The <see cref="AuthenticationRequest"/>.</param>
        public AuthenticationRequestResponse(AuthenticationRequest request)
        {
            Identifier = Guid.NewGuid();
            Authority = request.Authority;
            Request = request;
            Created = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// Initialializes new default instance of the <see cref=AuthenticationRequestResponse"/> class.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AuthenticationRequestResponse()
        { }

        /// <summary>
        /// Gets the <see cref="AuthenticationRequest"/> associated with this response.
        /// </summary>
        [JsonInclude]
        public AuthenticationRequest Request { get; internal set; } = new AuthenticationRequest();

        /// <summary>
        /// Gets whether or not this is valid response.
        /// </summary>
        [JsonIgnore]
        public override bool IsValid
        {
            get { return !Identifier.IsEmpty() && Request.IsValid; }
        }
    }
}
