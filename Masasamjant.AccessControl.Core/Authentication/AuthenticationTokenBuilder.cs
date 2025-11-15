using System.Security.Claims;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents abstract builder for authentication tokens.
    /// </summary>
    public abstract class AuthenticationTokenBuilder
    {
        /// <summary>
        /// Build authentication token string from <see cref="AuthenticationToken"/> instance.
        /// </summary>
        /// <param name="token">The authentication token.</param>
        /// <returns>A authentication token string.</returns>
        public abstract Task<string> BuildAuthenticationTokenAsync(AuthenticationToken token);

        /// <summary>
        /// Build <see cref="AuthenticationToken"/> instance from authentication token string.
        /// </summary>
        /// <param name="token">The authentication token string.</param>
        /// <param name="authority">The authority.</param>
        /// <returns>A <see cref="AuthenticationToken"/> or <c>null</c>.</returns>
        public abstract Task<AuthenticationToken?> BuildAuthenticationTokenAsync(string token, Authority authority);

        /// <summary>
        /// Creates <see cref="AuthoredIdentity"/> instance from specified claims.
        /// </summary>
        /// <param name="claims">The claims.</param>
        /// <returns>A <see cref="AuthoredIdentity"/>.</returns>
        protected AuthoredIdentity CreateAuthoredIdentity(IEnumerable<Claim> claims)
            => new AuthoredIdentity(claims);
    }
}
