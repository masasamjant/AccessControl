using System.Collections.Concurrent;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents repository that store <see cref="AuthenticationRequest"/> in memory.
    /// </summary>
    public sealed class AuthenticationRequestRepository : IAuthenticationRequestRepository
    {
        private static readonly ConcurrentDictionary<Guid, AuthenticationRequest> requests = new ConcurrentDictionary<Guid, AuthenticationRequest>();

        /// <summary>
        /// Gets the saved <see cref="AuthenticationRequest"/> from repository and removes it.
        /// </summary>
        /// <param name="identifier">The authentication request identifier.</param>
        /// <returns>A <see cref="AuthenticationRequest"/> or <c>null</c>, if not exist.</returns>
        public AuthenticationRequest? GetAuthenticationRequest(Guid identifier)
        {
            return requests.TryRemove(identifier, out var authenticationRequest) ? authenticationRequest : null;
        }

        /// <summary>
        /// Saves authentication request.
        /// </summary>
        /// <param name="request">The <see cref="AuthenticationRequest"/> to save.</param>
        public void SaveAuthenticationRequest(AuthenticationRequest request)
        {
            requests.AddOrUpdate(request.Identifier, request, (k, v) => request);
        }
    }
}
