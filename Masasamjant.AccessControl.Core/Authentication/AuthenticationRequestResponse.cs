using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents response to authentication request.
    /// </summary>
    public class AuthenticationRequestResponse : AuthenticationResponse
    {
        /// <summary>
        /// Initializes new default instance of the <see cref="AuthenticationRequestResponse"/> class with specified authentication request.
        /// </summary>
        /// <param name="request">The authentication request.</param>
        public AuthenticationRequestResponse(AuthenticationRequest request)
            : base(request.Authority)
        { }

        /// <summary>
        /// Initializes new default instance of the <see cref="AuthenticationRequestResponse"/> class that represents empty request.
        /// </summary>
        public AuthenticationRequestResponse()
            : base()
        { }

        /// <summary>
        /// Gets the authentication request.
        /// </summary>
        [JsonInclude]
        public AuthenticationRequest Request { get; internal set; } = new AuthenticationRequest();
    }
}
