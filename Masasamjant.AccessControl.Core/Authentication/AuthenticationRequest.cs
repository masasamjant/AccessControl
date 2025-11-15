using Masasamjant.Security.Abstractions;
using System.Globalization;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents request to authenticate <see cref="AuthoredIdentity"/>.
    /// </summary>
    public sealed class AuthenticationRequest : IAuthored
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationRequest"/> class.
        /// </summary>
        /// <param name="identity">The identity to authenticate.</param>
        /// <param name="secretType">The type of user secret use in authentication.</param>
        /// <exception cref="ArgumentException">If value of <paramref name="secretType"/> is not defined.</exception>
        public AuthenticationRequest(AuthoredIdentity identity, UserSecretType secretType)
        {
            if (!Enum.IsDefined(secretType))
                throw new ArgumentException("The value is not defined.", nameof(secretType));

            Identifier = Guid.NewGuid();
            Identity = identity;
            Created = DateTimeOffset.UtcNow;
            SecretType = secretType;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AuthenticationRequest"/> class that represents empty request.
        /// </summary>
        public AuthenticationRequest()
        { }

        /// <summary>
        /// Gets the unique identifier.
        /// </summary>
        [JsonInclude]
        public Guid Identifier { get; internal set; }

        /// <summary>
        /// Gets the <see cref="AuthoredIdentity"/> to authenticate.
        /// </summary>
        [JsonInclude]
        public AuthoredIdentity Identity { get; internal set; } = new AuthoredIdentity();

        /// <summary>
        /// Gets the UTC date and time when request was created.
        /// </summary>
        [JsonInclude]
        public DateTimeOffset Created { get; internal set; }

        /// <summary>
        /// Gets the type of user secret.
        /// </summary>
        [JsonInclude]
        public UserSecretType SecretType { get; internal set; }

        /// <summary>
        /// Gets the authority.
        /// </summary>
        [JsonIgnore]
        public Authority Authority
        { 
            get { return Identity.Authority; }
        }

        /// <summary>
        /// Creates new <see cref="AuthenticationChallenge"/> for this request.
        /// </summary>
        /// <param name="userSecret">The user secret.</param>
        /// <param name="hashProvider">The hash provider.</param>
        /// <returns>A authentication challenge.</returns>
        /// <exception cref="ArgumentException">If data of <paramref name="userSecret"/> is empty.</exception>
        public AuthenticationChallenge CreateAuthenticationChallenge(IUserSecret userSecret, IHashProvider hashProvider)
        {
            if (userSecret.Data.Length == 0)
                throw new ArgumentException("The user secret data is empty.", nameof(userSecret));

            return new AuthenticationChallenge(this, userSecret.Data, hashProvider);
        }

        /// <summary>
        /// Create hash bytes for this request using specified <see cref="IHashProvider"/>.
        /// </summary>
        /// <param name="hashProvider">The <see cref="IHashProvider"/>.</param>
        /// <returns>A hash bytes for this request.</returns>
        public byte[] CreateRequestHash(IHashProvider hashProvider)
        {
            var value = string.Concat(Identifier, Identity.Name, Created.ToString(CultureInfo.InvariantCulture), Authority.Name, Authority.Uri);
            var data = value.GetByteArray();
            return hashProvider.HashData(data);
        }
    }
}
