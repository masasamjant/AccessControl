using System.Collections.Concurrent;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents repository to store authentication requests. The default implementation stores them in-memory.
    /// </summary>
    public class AuthenticationRequestRepository : IAuthenticationRequestRepository
    {
        private static readonly Lazy<ConcurrentDictionary<Guid, AuthenticationRequest>> items 
            = new Lazy<ConcurrentDictionary<Guid, AuthenticationRequest>>(() => new ConcurrentDictionary<Guid, AuthenticationRequest>());

        /// <summary>
        /// Gets the <see cref="AuthenticationRequest"/> stored and removes it from storage if available.
        /// </summary>
        /// <param name="requestIdentifier">The authentication request identifier.</param>
        /// <returns>A <see cref="AuthenticationRequest"/> or <c>null</c>.</returns>
        public virtual Task<AuthenticationRequest?> GetAuthenticationRequestAsync(Guid requestIdentifier)
        {
            AuthenticationRequest? request = null;

            if (Items.TryRemove(requestIdentifier, out var item))
                request = item;

            return Task.FromResult(request);
        }

        /// <summary>
        /// Temporary store <see cref="AuthenticationRequest"/> during authentication process. 
        /// </summary>
        /// <param name="request">The <see cref="AuthenticationRequest"/> to store.</param>
        public virtual Task SaveAuthenticationRequestAsync(AuthenticationRequest request)
        {
            Items.AddOrUpdate(request.Identifier, request, (K, v) => request);
            return Task.CompletedTask;
        }

        private static ConcurrentDictionary<Guid, AuthenticationRequest> Items
        { 
            get { return items.Value; }
        }
    }
}
