using Masasamjant.Security.Abstractions;
using System.Globalization;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents request to authenticate <see cref="AuthoredIdentity"/>.
    /// </summary>
    public class AuthenticationRequest : IAuthored
    {
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
        /// <param name="secretProvider">The <see cref="IUserSecretProvider"/>.</param>
        /// <param name="hashProvider">The <see cref="IHashProvider"/>.</param>
        /// <returns>A <see cref="AuthenticationChallenge"/>.</returns>
        /// <exception cref="InvalidOperationException">If user does not have <see cref="SecretType"/> secret.</exception>
        public async Task<AuthenticationChallenge> CreateAuthenticationChallengeAsync(IUserSecretProvider secretProvider, IHashProvider hashProvider)
        {
            var userSecret = await secretProvider.GetUserSecretAsync(Identity.Name, SecretType);
            var userSecretData = userSecret?.Data ?? throw new InvalidOperationException($"User '{Identity.Name}' do not have '{SecretType}' secret.");
            return CreateAuthenticationChallenge(userSecretData, hashProvider);
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

        internal AuthenticationChallenge CreateAuthenticationChallenge(byte[] identitySecret, IHashProvider hashProvider)
        {
            return new AuthenticationChallenge(this, identitySecret, hashProvider);
        }
    }
}
