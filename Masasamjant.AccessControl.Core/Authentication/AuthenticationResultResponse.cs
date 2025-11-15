using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authentication result response containing the authored principal.
    /// </summary>
    public sealed class AuthenticationResultResponse : AuthenticationResponse
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationResultResponse"/> class based on the specified authored principal.
        /// </summary>
        /// <param name="principal">The authored principal.</param>
        /// <param name="authenticationToken">The authentication token.</param>
        public AuthenticationResultResponse(AuthoredPrincipal principal, string authenticationToken)
            : base(principal.Authority)
        {
            Principal = principal;
            AuthenticationToken = principal.Identity.IsAuthenticated ? authenticationToken : string.Empty;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AuthenticationResultResponse"/> class 
        /// that represents unauthenticated result.
        /// </summary>
        public AuthenticationResultResponse()
        { }

        /// <summary>
        /// Gets the authored principal.
        /// </summary>
        [JsonInclude]
        public AuthoredPrincipal Principal { get; internal set; } = new AuthoredPrincipal();

        /// <summary>
        /// Gets the authentication token or empty string if not authenticated.
        /// </summary>
        [JsonInclude]
        public string AuthenticationToken { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets the authentication result.
        /// </summary>
        [JsonIgnore]
        public AuthenticationResult Result
        {
            get
            {
                if (Principal.Identity.IsAuthenticated)
                    return AuthenticationResult.Authenticated;

                return AuthenticationResult.Unauthenticated;
            }
        }
    }
}
