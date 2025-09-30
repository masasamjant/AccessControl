using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authentication response.
    /// </summary>
    public class AuthenticationResultResponse : AuthenticationResponse
    {
        internal AuthenticationResultResponse(AccessControlPrincipal? principal, string authority)
        {
            Principal = principal;
            Authority = authority;
            Identifier = Guid.NewGuid();
            Created = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// Initializes new invalid instance of the <see cref="AuthenticationResultResponse"/> class.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AuthenticationResultResponse()
        { }

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
                if (Principal != null && Principal.Identity.IsAuthenticated)
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
