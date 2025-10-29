using Masasamjant.Security.Abstractions;
using System.Globalization;
using System.Text;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents request to authenticate identity.
    /// </summary>
    public sealed class AuthenticationRequest : IAuthenticationItem
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationRequest"/> class.
        /// </summary>
        /// <param name="authority">The name of authority.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="authority"/> or <paramref name="authenticationScheme"/> is empty or only whitespace.</exception>
        public AuthenticationRequest(AccessControlIdentity identity, string authority, string authenticationScheme)
        {
            if (string.IsNullOrWhiteSpace(authority))
                throw new ArgumentNullException(nameof(authority), "The authority is empty or only whitespace.");

            if (string.IsNullOrWhiteSpace(authenticationScheme))
                throw new ArgumentNullException(nameof(authenticationScheme), "The authentication scheme is empty or only whitespace.");

            Identifier = Guid.NewGuid();
            Identity = identity;
            Created = DateTimeOffset.UtcNow;
            Authority = authority;
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
        public AccessControlIdentity Identity { get; internal set; } = new AccessControlIdentity();

        /// <summary>
        /// Gets the UTC time when request was created.
        /// </summary>
        [JsonInclude]
        public DateTimeOffset Created { get; internal set; }

        /// <summary>
        /// Gets the name of authority associated with this request.
        /// </summary>
        [JsonInclude]
        public string Authority { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets if or not request is valid.
        /// </summary>
        [JsonIgnore]
        public bool IsValid
        {
            get { return !Identifier.IsEmpty() && Identity.IsValid; }
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
        public byte[] CreateRequestHash(IHashProvider hashProvider)
        {
            if (!IsValid)
                return [];

            var value = string.Concat(Identifier, Identity.Name, Created.ToString(CultureInfo.InvariantCulture), Authority, AuthenticationScheme);
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
        public AuthenticationChallenge CreateAuthenticationChallenge(byte[] secret, IHashProvider hashProvider)
        {
            if (!IsValid)
                throw new InvalidOperationException("Authentication request is not valid.");

            return new AuthenticationChallenge(this, secret, hashProvider);
        }
    }
}
