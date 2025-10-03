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
        public Task<AuthenticationRequest?> GetAuthenticationRequestAsync(Guid identifier)
        {
            var request = requests.TryRemove(identifier, out var authenticationRequest) ? authenticationRequest : null;
            return Task.FromResult(request);
        }

        /// <summary>
        /// Saves authentication request.
        /// </summary>
        /// <param name="request">The <see cref="AuthenticationRequest"/> to save.</param>
        public Task SaveAuthenticationRequestAsync(AuthenticationRequest request)
        {
            requests.AddOrUpdate(request.Identifier, request, (k, v) => request);
            return Task.CompletedTask;
        }
    }
}
