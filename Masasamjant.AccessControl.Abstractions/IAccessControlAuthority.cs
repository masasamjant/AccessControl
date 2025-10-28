using Masasamjant.AccessControl.Authentication;
using Masasamjant.AccessControl.Authorization;
using Masasamjant.AccessControl.Authorization.Policies;
using Microsoft.Extensions.Logging;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents access control authority.
    /// </summary>
    public interface IAccessControlAuthority : IAuthenticationSecretProvider, IAuthenticationTokenFactory, IPrincipalClaimProvider, IPrincipalRoleProvider, IAuthorizationEvaluatorFactory, IAccessPolicyEvaluationFactory
    {
        /// <summary>
        /// Gets the name of the authority.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Gets the <see cref="IAuthenticationItemValidator"/>.
        /// </summary>
        IAuthenticationItemValidator ItemValidator { get; }

        /// <summary>
        /// Gets the logger factory.
        /// </summary>
        ILoggerFactory LoggerFactory { get; }

        /// <summary>
        /// Creates new authentication request authorized by this authority.
        /// </summary>
        /// <param name="identity">The identity of the principal.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns>A <see cref="AuthenticationRequest"/>.</returns>
        /// <exception cref="ArgumentNullException">If value of <paramref name="authenticationScheme"/> is empty or only whitespace.</exception>
        /// <exception cref="NotSupportedException">If authentication scheme specified by <paramref name="authenticationScheme"/> is not supported.</exception>
        AuthenticationRequest CreateAuthenticationRequest(AccessControlIdentity identity, string authenticationScheme);

        /// <summary>
        /// Gets the <see cref="AccessControlIdentity"/> that represents authenticated identity.
        /// </summary>
        /// <param name="identity">The <see cref="AccessControlIdentity"/> that represents unauthenticated identity.</param>
        /// <returns>A <see cref="AccessControlIdentity"/> that represents authenticated identity.</returns>
        AccessControlIdentity GetAuthenticatedIdentity(AccessControlIdentity identity);

        /// <summary>
        /// Check if is authoring specified <see cref="IAuthenticationItem"/>.
        /// </summary>
        /// <param name="item">The <see cref="IAuthenticationItem"/>.</param>
        /// <returns><c>true</c> if <paramref name="item"/> is authorized by this authority; <c>false</c> otherwise.</returns>
        bool IsAuthoring(IAuthenticationItem item);

        /// <summary>
        /// Check if is authoring specified <see cref="AccessControlIdentity"/>.
        /// </summary>
        /// <param name="identity">The <see cref="AccessControlIdentity"/>.</param>
        /// <returns><c>true</c> if authoring <paramref name="identity"/>; <c>false</c> otherwise.</returns>
        bool IsAuthoring(AccessControlIdentity identity);

        /// <summary>
        /// Check if this authority supports specified authentication scheme.
        /// </summary>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns><c>true</c> if specified authentication scheme is supported; <c>false</c> otherwise.</returns>
        bool IsSupportedAuthentication(string authenticationScheme);
    }
}
