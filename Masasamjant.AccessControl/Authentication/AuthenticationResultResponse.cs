using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authentication response.
    /// </summary>
    public class AuthenticationResultResponse : IAuthenticationItem
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationResultResponse"/> class.
        /// </summary>
        /// <param name="result">The <see cref="AuthenticationResult"/>.</param>
        /// <param name="token">The <see cref="AuthenticationToken"/>.</param>
        /// <param name="unauthenticatedReason">The unauthenticated reason or <c>null</c>.</param>
        /// <exception cref="ArgumentException">
        /// If value of <paramref name="result"/> is not defined.
        /// -or-
        /// If authenticate, but <paramref name="token"/> is not valid.
        /// </exception>
        /// <exception cref="ArgumentNullException">If authenticated, but <paramref name="token"/> is <c>null</c>.</exception>
        internal AuthenticationResultResponse(AuthenticationResult result, AuthenticationToken? token, string? unauthenticatedReason)
        {
            if (!Enum.IsDefined(result))
                throw new ArgumentException("The value is not defined.", nameof(result));

            if (result == AuthenticationResult.Unauthenticated)
            {
                Result = result;
                Token = new AuthenticationToken();
                UnauthenticatedReason = unauthenticatedReason;
            }
            else
            {
                if (token == null)
                    throw new ArgumentNullException(nameof(token), "The authentication token is not set.");

                if (!token.IsValid)
                    throw new ArgumentException("The authentication token is not valid.", nameof(token));

                Result = result;
                Token = token;
                UnauthenticatedReason = null;
            }

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
        /// Gets the unique identifier of this response.
        /// </summary>
        [JsonInclude]
        public Guid Identifier { get; internal set; }

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
        public AuthenticationToken Token { get; internal set; } = new AuthenticationToken();

        /// <summary>
        /// Gets the reason text for unauthentication, if used. <c>null</c> otherwise.
        /// </summary>
        [JsonInclude]
        public string? UnauthenticatedReason { get; internal set; }

        /// <summary>
        /// Gets the UTC date and time when response was created.
        /// </summary>
        [JsonInclude]
        public DateTimeOffset Created { get; internal set; }

        /// <summary>
        /// Gets if or not this is valid response.
        /// </summary>
        [JsonIgnore]
        public bool IsValid
        {
            get { return !Identifier.IsEmpty(); }
        }
    }
}
