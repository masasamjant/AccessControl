using Masasamjant.Security.Abstractions;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authentication challenge.
    /// </summary>
    public sealed class AuthenticationChallenge : IAuthored
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationChallenge"/> class for specified <see cref="AuthenticationRequest"/>.
        /// </summary>
        /// <param name="request">The authentication request.</param>
        /// <param name="identitySecret">The secret of <see cref="AuthenticationRequest.Identity"/>.</param>
        /// <param name="hashProvider">The hash provider.</param>
        public AuthenticationChallenge(AuthenticationRequest request, byte[] identitySecret, IHashProvider hashProvider)
        {
            RequestIdentifier = request.Identifier;
            Authority = request.Authority;
            Created = DateTimeOffset.UtcNow;
            var requestHash = request.CreateRequestHash(hashProvider);
            var combine = ArrayHelper.Combine(requestHash, identitySecret);
            Data = hashProvider.HashData(combine);
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AuthenticationChallenge"/> class that represents empty challenge.
        /// </summary>
        public AuthenticationChallenge()
        { }

        /// <summary>
        /// Gets the authentication request identifier.
        /// </summary>
        public Guid RequestIdentifier { get; internal set; }

        /// <summary>
        /// Gets the authority.
        /// </summary>
        public Authority Authority { get; internal set; } = new Authority();
        
        /// <summary>
        /// Gets the UTC date and time when challenge was created.
        /// </summary>
        public DateTimeOffset Created { get; internal set; }

        /// <summary>
        /// Gets the challenge data.
        /// </summary>
        public byte[] Data { get; internal set; } = [];
    }
}
