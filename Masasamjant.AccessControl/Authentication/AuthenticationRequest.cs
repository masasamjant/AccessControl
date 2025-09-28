using Masasamjant.Security.Abstractions;
using System.Globalization;
using System.Text;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents request to authenticate identity.
    /// </summary>
    public class AuthenticationRequest : IAuthenticationItem
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationRequest"/> class.
        /// </summary>
        /// <param name="principal">The <see cref="IAccessControlPrincipal"/> to authenticate.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="authenticationScheme"/> is empty or only whitespace.</exception>
        public AuthenticationRequest(string identity, string authenticationScheme)
        {
            if (string.IsNullOrWhiteSpace(authenticationScheme))
                throw new ArgumentNullException(nameof(authenticationScheme), "The authentication scheme can not be empty or only whitespace.");

            Identifier = Guid.NewGuid();
            Identity = identity;
            Created = DateTimeOffset.UtcNow;
            AuthenticationScheme = authenticationScheme;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AuthenticationRequest"/> class.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AuthenticationRequest() 
        { }

        /// <summary>
        /// Gets the unique identifier of this request.
        /// </summary>
        [JsonInclude]
        public Guid Identifier { get; internal set; }

        /// <summary>
        /// Gets the user identity. This can be any unique value to identify user, like user name or email address or phone number etc., in application.
        /// </summary>
        [JsonInclude]   
        public string Identity { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets the UTC time when request was created.
        /// </summary>
        [JsonInclude]
        public DateTimeOffset Created { get; internal set; }

        /// <summary>
        /// Gets if or not request is valid.
        /// </summary>
        [JsonIgnore]
        public bool IsValid
        {
            get { return !Identifier.IsEmpty() && !string.IsNullOrWhiteSpace(Identity); }
        }

        /// <summary>
        /// Gets the authentication scheme. Depends on implementation.
        /// </summary>
        [JsonInclude]
        public string AuthenticationScheme { get; internal set; } = string.Empty;

        /// <summary>
        /// Computes string hash for this request.
        /// </summary>
        /// <param name="hashProvider">The <see cref="IHashProvider"/>.</param>
        /// <returns>A hash string.</returns>
        /// <remarks>If <see cref="IsValid"/> is <c>false</c>, then returns empty string.</remarks>
        internal byte[] CreateRequestHash(IHashProvider hashProvider)
        {
            if (!IsValid)
                return [];

            var value = string.Concat(Identifier, Identity, Created.ToString(CultureInfo.InvariantCulture));
            var data = Encoding.Unicode.GetBytes(value);
            return hashProvider.HashData(data);
        }

        /// <summary>
        /// Creates new <see cref="AuthenticationChallenge"/> that is associated with this request.
        /// </summary>
        /// <param name="secret">The secret.</param>
        /// <param name="hashProvider">The <see cref="IHashProvider"/>.</param>
        /// <returns>A <see cref="AuthenticationChallenge"/>.</returns>
        /// <exception cref="InvalidOperationException">If this request is not valid.</exception>
        internal AuthenticationChallenge CreateAuthenticationChallenge(byte[] secret, IHashProvider hashProvider)
        {
            if (!IsValid)
                throw new InvalidOperationException("Authentication response is not valid.");

            return new AuthenticationChallenge(this, secret, hashProvider);
        }
    }
}
