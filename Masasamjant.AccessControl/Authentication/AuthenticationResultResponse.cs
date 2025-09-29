using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authentication response.
    /// </summary>
    public class AuthenticationResultResponse : AuthenticationResponse
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationResultResponse"/> class.
        /// </summary>
        /// <param name="result">The <see cref="AuthenticationResult"/>.</param>
        /// <param name="authenticationToken">The authentication token string.</param>
        /// <param name="authority">The authority name.</param>
        /// <param name="claims">The claims if authenticated.</param>
        /// <param name="unauthenticatedReason">The unauthenticated reason or <c>null</c>.</param>
        /// <exception cref="ArgumentException">
        /// If value of <paramref name="result"/> is not defined.
        /// -or-
        /// If authenticate, but <paramref name="token"/> is not valid.
        /// </exception>
        /// <exception cref="ArgumentNullException">If authenticated, but <paramref name="token"/> is <c>null</c>.</exception>
        internal AuthenticationResultResponse(AuthenticationResult result, string? authenticationToken, string authority, IEnumerable<AccessControlClaim> claims, string? unauthenticatedReason)
        {
            if (!Enum.IsDefined(result))
                throw new ArgumentException("The value is not defined.", nameof(result));

            if (result == AuthenticationResult.Unauthenticated)
            {
                Result = result;
                AuthenticationToken = string.Empty;
                UnauthenticatedReason = unauthenticatedReason;
            }
            else
            {
                if (string.IsNullOrWhiteSpace(authenticationToken))
                    throw new ArgumentNullException(nameof(authenticationToken), "The authentication token is null, empty or only whitespace.");

                Result = result;
                AuthenticationToken = authenticationToken;
                UnauthenticatedReason = null;
                Claims = claims.ToArray();
            }

            Authority = authority;
            Identifier = Guid.NewGuid();
            Created = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// Factory method create <see cref="AuthenticationResultResponse"/> of unauthentication.
        /// </summary>
        /// <param name="authority">The authority name.</param>
        /// <param name="unauthenticatedReason">The unauthenticated reason.</param>
        /// <returns>A <see cref="AuthenticationResultResponse"/> of unauthentication.</returns>
        internal static AuthenticationResultResponse Unauthenticated(string authority, string? unauthenticatedReason)
            => new AuthenticationResultResponse(AuthenticationResult.Unauthenticated, null, authority, [], unauthenticatedReason);

        /// <summary>
        /// Initializes new invalid instance of the <see cref="AuthenticationResultResponse"/> class.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AuthenticationResultResponse()
        { }

        /// <summary>
        /// Gets the <see cref="AuthenticationResult"/>.
        /// </summary>
        [JsonInclude]
        public AuthenticationResult Result { get; internal set; }

        /// <summary>
        /// Gets the <see cref="AuthenticationToken"/>.
        /// </summary>
        /// <remarks>Is not valid when <see cref="Result"/> is <see cref="AuthenticationResult.Unauthenticated"/>.</remarks>
        [JsonInclude]
        public string AuthenticationToken { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets the reason text for unauthentication, if used. <c>null</c> otherwise.
        /// </summary>
        [JsonInclude]
        public string? UnauthenticatedReason { get; internal set; }

        /// <summary>
        /// Gets the claims.
        /// </summary>
        [JsonInclude]
        public AccessControlClaim[] Claims { get; internal set; } = [];

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
