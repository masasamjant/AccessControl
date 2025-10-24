using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authentication response.
    /// </summary>
    public sealed class AuthenticationResultResponse : AuthenticationResponse
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationResultResponse"/> class.
        /// </summary>
        /// <param name="principal">The <see cref="AccessControlPrincipal"/> if authenticated; <c>null</c> otherwise.</param>
        /// <param name="authority">The <see cref="IAccessControlAuthority"/>.</param>
        public AuthenticationResultResponse(AccessControlPrincipal? principal, IAccessControlAuthority authority)
        {
            Principal = principal;
            Authority = authority.Name;
            Identifier = Guid.NewGuid();
            Created = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// Initializes new invalid instance of the <see cref="AuthenticationResultResponse"/> class.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AuthenticationResultResponse()
        { }

        /// <summary>
        /// Gets the <see cref="AccessControlPrincipal"/> associated with response, if authenticated.
        /// </summary>
        [JsonInclude]
        public AccessControlPrincipal? Principal { get; internal set; }

        /// <summary>
        /// Gets the <see cref="AuthenticationResult"/>.
        /// </summary>
        [JsonIgnore]
        public AuthenticationResult Result
        {
            get
            {
                if (Principal.IsAuthenticatePrincipal())
                    return AuthenticationResult.Authenticated;

                return AuthenticationResult.Unauthenticated;
            }
        }

        /// <summary>
        /// Gets the reason text for unauthentication, if used. <c>null</c> otherwise.
        /// </summary>
        [JsonInclude]
        public string? UnauthenticatedReason { get; internal set; }

        /// <summary>
        /// Gets if or not this is valid response.
        /// </summary>
        [JsonIgnore]
        public override bool IsValid
        {
            get { return !Identifier.IsEmpty(); }
        }
    }
}
