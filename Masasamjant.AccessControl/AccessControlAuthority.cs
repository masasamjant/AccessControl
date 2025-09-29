using Masasamjant.AccessControl.Authentication;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents abstract access control authority.
    /// </summary>
    public abstract class AccessControlAuthority : IAccessControlPrincipalProvider, IAuthenticationSecretProvider
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessControlAuthority"/> class.
        /// </summary>
        /// <param name="name">The authority name.</param>
        /// <param name="principalProvider">The <see cref="IAccessControlPrincipalProvider"/>.</param>
        /// <param name="secretProvider">The <see cref="IAuthenticationSecretProvider"/>.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="name"/> is empty or only whitespace.</exception>
        protected AccessControlAuthority(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The authority name is empty or only whitespace.");

            Name = name;
        }

        /// <summary>
        /// Gets the name of the authority.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Gets the authentication schemes supported by this authority
        /// </summary>
        /// <remarks>If empty, then should support any authentication scheme.</remarks>
        protected abstract string[] AuthenticationSchemes { get; }

        /// <summary>
        /// Creates authentication token string for access control principal.
        /// </summary>
        /// <param name="principal">The <see cref="IAccessControlPrincipal"/>.</param>
        /// <returns>A authentication token string.</returns>
        public string GetAuthenticationToken(IAccessControlPrincipal principal)
        {
            var claims = new List<AccessControlClaim>();
            
            foreach (var claim in principal.GetClaims())
                claims.Add(new AccessControlClaim(claim.Key, claim.Value, Name));
            
            var authenticationToken = new AuthenticationToken(principal.GetAccessControlIdentity().Name, Name, claims);

            return CreateAuthenticationToken(authenticationToken);
        }

        /// <summary>
        /// Creates new authentication request authorized by this authority.
        /// </summary>
        /// <param name="identity">The identity of the principal.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns>A <see cref="AuthenticationRequest"/>.</returns>
        /// <exception cref="ArgumentNullException">If value of <paramref name="authenticationScheme"/> is empty or only whitespace.</exception>
        /// <exception cref="NotSupportedException">If authentication scheme specified by <paramref name="authenticationScheme"/> is not supported.</exception>
        public AuthenticationRequest CreateAuthenticationRequest(string identity, string authenticationScheme)
        {
            if (string.IsNullOrWhiteSpace(authenticationScheme))
                throw new ArgumentNullException(nameof(authenticationScheme), "The authentication scheme is empty or only whitespace.");

            if (AuthenticationSchemes.Length > 0 && !AuthenticationSchemes.Contains(authenticationScheme))
                throw new NotSupportedException($"Authentication scheme '{authenticationScheme}' is not supported by '{Name}' authority.");

            return new AuthenticationRequest(identity, Name, authenticationScheme);
        }

        /// <summary>
        /// Check if <see cref="IAuthenticationItem"/> is authorized by this authority.
        /// </summary>
        /// <param name="item">The <see cref="IAuthenticationItem"/>.</param>
        /// <returns><c>true</c> if <paramref name="item"/> is authorized by this authority; <c>false</c> otherwise.</returns>
        public bool IsAuthorized(IAuthenticationItem item)
        {
            return item.Authority == Name;
        }

        /// <summary>
        /// Gets <see cref="AuthenticationToken"/> from specified authentication token string.
        /// </summary>
        /// <param name="authenticationTokenString">The authentication token string.</param>
        /// <returns>A <see cref="AuthenticationToken"/>.</returns>
        public abstract AuthenticationToken GetAuthenticationToken(string authenticationTokenString);

        /// <summary>
        /// Creates string value from specified authentication token.
        /// </summary>
        /// <param name="authenticationToken">The <see cref="AuthenticationToken"/>.</param>
        /// <returns>A authentication token string.</returns>
        protected abstract string CreateAuthenticationToken(AuthenticationToken authenticationToken);

        /// <summary>
        /// Gets <see cref="IAccessControlPrincipal"/> by name.
        /// </summary>
        /// <param name="name">The principal name.</param>
        /// <returns>A <see cref="IAccessControlPrincipal"/> or <c>null</c>, if not exist.</returns>
        public abstract IAccessControlPrincipal? GetAccessControlPrincipal(string name);

        /// <summary>
        /// Gets the secret of the specified identity for the specified authentication scheme.
        /// </summary>
        /// <param name="identity">The identity whose secret should be get.</param>
        /// <param name="authenticationScheme">The authentication scheme. The value depends on implementation.</param>
        /// <returns>A data of the secter or empty array if there is not such identity or if identity do not have secret in specified authentication scheme.</returns>
        /// <exception cref="ArgumentNullException">If value of <paramref name="authenticationScheme"/> is empty or only whitespace.</exception>
        /// <exception cref="NotSupportedException">If authentication scheme specified by <paramref name="authenticationScheme"/> is not supported.</exception>
        public byte[] GetAuthenticationSecret(string identity, string authenticationScheme)
        {
            if (string.IsNullOrWhiteSpace(authenticationScheme))
                throw new ArgumentNullException(nameof(authenticationScheme), "The authentication scheme is empty or only whitespace.");

            if (AuthenticationSchemes.Length > 0 && !AuthenticationSchemes.Contains(authenticationScheme))
                throw new NotSupportedException($"Authentication scheme '{authenticationScheme}' is not supported by '{Name}' authority.");

            return GetIdentityAuthenticationSecret(identity, authenticationScheme);
        }

        /// <summary>
        /// Gets the secret of the specified identity for the specified authentication scheme.
        /// </summary>
        /// <param name="identity">The identity whose secret should be get.</param>
        /// <param name="authenticationScheme">The authentication scheme. The value depends on implementation.</param>
        /// <returns>A data of the secter or empty array if there is not such identity or if identity do not have secret in specified authentication scheme.</returns>
        /// <remarks><paramref name="authenticationScheme"/> is already validated to be one of the supported ones.</remarks>
        protected abstract byte[] GetIdentityAuthenticationSecret(string identity, string authenticationScheme);
    }
}
