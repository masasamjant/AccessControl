using Masasamjant.AccessControl.Authentication;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents abstract access control authority.
    /// </summary>
    public abstract class AccessControlAuthority : IAccessControlAuthority, IAuthenticationSecretProvider, IAuthenticationTokenFactory, IPrincipalClaimProvider, IPrincipalRoleProvider
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessControlAuthority"/> class.
        /// </summary>
        /// <param name="name">The authority name.</param>
        /// <param name="itemValidator">The custom authentication item validator.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="name"/> is empty or only whitespace.</exception>
        protected AccessControlAuthority(string name, IAuthenticationItemValidator itemValidator)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The authority name is empty or only whitespace.");

            Name = name;
            ItemValidator = itemValidator;
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
        /// Gets the <see cref="IAuthenticationItemValidator"/>.
        /// </summary>
        protected IAuthenticationItemValidator ItemValidator { get; }

        /// <summary>
        /// Creates new authentication request authorized by this authority.
        /// </summary>
        /// <param name="identity">The identity of the principal.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns>A <see cref="AuthenticationRequest"/>.</returns>
        /// <exception cref="ArgumentNullException">If value of <paramref name="authenticationScheme"/> is empty or only whitespace.</exception>
        /// <exception cref="NotSupportedException">If authentication scheme specified by <paramref name="authenticationScheme"/> is not supported.</exception>
        public AuthenticationRequest CreateAuthenticationRequest(AccessControlIdentity identity, string authenticationScheme)
        {
            CheckAuthenticationScheme(authenticationScheme);

            return new AuthenticationRequest(identity, this, authenticationScheme);
        }

        /// <summary>
        /// Check if this authority supports specified authentication scheme.
        /// </summary>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns><c>true</c> if specified authentication scheme is supported; <c>false</c> otherwise.</returns>
        public bool IsSupportedAuthentication(string authenticationScheme)
        {
            // If empty, then should support all schemes. Otherwise check if contains specified scheme.
            return AuthenticationSchemes.Length == 0 || AuthenticationSchemes.Contains(authenticationScheme);
        }

        /// <summary>
        /// Creates authentication token string for access control principal.
        /// </summary>
        /// <param name="principal">The <see cref="AccessControlPrincipal"/>.</param>
        /// <returns>A authentication token string.</returns>
        public string CreateAuthenticationToken(AccessControlPrincipal principal, string authenticationScheme)
        {
            CheckAuthenticationScheme(authenticationScheme);

            var identity = principal.Identity;

            if (!identity.IsValid || !identity.IsAuthenticated)
                return string.Empty;

            var claims = new List<AccessControlClaim>();
            
            foreach (var claim in principal.Claims)
                claims.Add(new AccessControlClaim(claim.Key, claim.Value, this));
            
            var authenticationToken = new AuthenticationToken(identity, this, authenticationScheme, claims, principal.Roles);

            return CreateAuthenticationToken(authenticationToken);
        }

        /// <summary>
        /// Creates <see cref="AuthenticationToken"/> from specified authentication token string.
        /// </summary>
        /// <param name="authenticationTokenString">The authentication token string.</param>
        /// <returns>A <see cref="AuthenticationToken"/>.</returns>
        public abstract AuthenticationToken CreateAuthenticationToken(string authenticationTokenString);

        /// <summary>
        /// Creates string value from specified authentication token.
        /// </summary>
        /// <param name="authenticationToken">The <see cref="AuthenticationToken"/>.</param>
        /// <returns>A authentication token string.</returns>
        protected abstract string CreateAuthenticationToken(AuthenticationToken authenticationToken);

        /// <summary>
        /// Check if is authoring specified <see cref="IAuthenticationItem"/>.
        /// </summary>
        /// <param name="item">The <see cref="IAuthenticationItem"/>.</param>
        /// <returns><c>true</c> if <paramref name="item"/> is authorized by this authority; <c>false</c> otherwise.</returns>
        public bool IsAuthoring(IAuthenticationItem item)
        {
            return item.Authority == Name;
        }

        /// <summary>
        /// Check if is authoring specified <see cref="AccessControlIdentity"/>.
        /// </summary>
        /// <param name="identity">The <see cref="AccessControlIdentity"/>.</param>
        /// <returns><c>true</c> if authoring <paramref name="identity"/>; <c>false</c> otherwise.</returns>
        public abstract bool IsAuthoring(AccessControlIdentity identity);

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
            CheckAuthenticationScheme(authenticationScheme);

            return GetIdentityAuthenticationSecret(identity, authenticationScheme);
        }

        /// <summary>
        /// Gets the <see cref="AccessControlIdentity"/> that represents authenticated identity.
        /// </summary>
        /// <param name="identity">The <see cref="AccessControlIdentity"/> that represents unauthenticated identity.</param>
        /// <returns>A <see cref="AccessControlIdentity"/> that represents authenticated identity.</returns>
        public abstract AccessControlIdentity GetAuthenticatedIdentity(AccessControlIdentity identity);

        /// <summary>
        /// Gets the secret of the specified identity for the specified authentication scheme.
        /// </summary>
        /// <param name="identity">The identity whose secret should be get.</param>
        /// <param name="authenticationScheme">The authentication scheme. The value depends on implementation.</param>
        /// <returns>A data of the secter or empty array if there is not such identity or if identity do not have secret in specified authentication scheme.</returns>
        /// <remarks><paramref name="authenticationScheme"/> is already validated to be one of the supported ones.</remarks>
        protected abstract byte[] GetIdentityAuthenticationSecret(string identity, string authenticationScheme);

        public virtual IEnumerable<AccessControlClaim> GetPrincipalClaims(AccessControlPrincipal principal) => [];

        public virtual IEnumerable<string> GetPrincipalRoles(AccessControlPrincipal principal) => [];

        /// <summary>
        /// Validates that value of <paramref name="authenticationScheme"/> is not empty or only whitespace and that it is supported. 
        /// </summary>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="authenticationScheme"/> is empty or only whitespace.</exception>
        /// <exception cref="NotSupportedException">If value of <paramref name="authenticationScheme"/> is not supported.</exception>
        protected void CheckAuthenticationScheme(string authenticationScheme)
        {
            if (string.IsNullOrWhiteSpace(authenticationScheme))
                throw new ArgumentNullException(nameof(authenticationScheme), "The authentication scheme is empty or only whitespace.");

            if (!IsSupportedAuthentication(authenticationScheme))
                throw new NotSupportedException($"Authentication scheme '{authenticationScheme}' is not supported by '{Name}' authority.");
        }
    }
}
