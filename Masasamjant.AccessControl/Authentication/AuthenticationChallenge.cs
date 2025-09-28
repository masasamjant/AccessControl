using Masasamjant.Security.Abstractions;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authentication challenge.
    /// </summary>
    public class AuthenticationChallenge : IAuthenticationItem
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationChallenge"/> class.
        /// </summary>
        /// <param name="request">The <see cref="AuthenticationRequest"/> associated with challenge.</param>
        /// <param name="secret">The secret.</param>
        /// <param name="hashProvider">The <see cref="IHashProvider"/>.</param>
        /// <exception cref="AuthenticationException">If <paramref name="request"/> is not valid <see cref="AuthenticationRequest"/>.</exception>
        internal AuthenticationChallenge(AuthenticationRequest request, byte[] secret, IHashProvider hashProvider)
        {
            if (!request.IsValid)
                throw new AuthenticationException("Authentication request is not valid.", request);

            Identifier = request.Identifier;
            Created = DateTimeOffset.Now;
            byte[] requestHash = request.CreateRequestHash(hashProvider);
            byte[] combine = ArrayHelper.Combine(requestHash, secret);
            Data = hashProvider.HashData(combine);
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AuthenticationChallenge"/> class.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AuthenticationChallenge()
        { }

        /// <summary>
        /// Gets the unique identifier of authentication request of this challenge.
        /// </summary>
        [JsonInclude]
        public Guid Identifier { get; internal set; }

        /// <summary>
        /// Gets the UTC date and time when challenge was created.
        /// </summary>
        [JsonInclude]
        public DateTimeOffset Created { get; internal set; }

        /// <summary>
        /// Gets if or not challenge is valid.
        /// </summary>
        [JsonIgnore]
        public bool IsValid
        {
            get { return !Identifier.IsEmpty(); }
        }

        /// <summary>
        /// Gets the challenge data.
        /// </summary>
        [JsonInclude]
        public byte[] Data { get; internal set; } = [];
    }
}
