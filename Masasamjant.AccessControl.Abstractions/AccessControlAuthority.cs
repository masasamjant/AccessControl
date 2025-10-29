using Masasamjant.AccessControl.Authentication;
using Masasamjant.AccessControl.Authorization;
using Masasamjant.AccessControl.Authorization.Policies;
using Microsoft.Extensions.Logging;
using System.Reflection;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents abstract access control authority.
    /// </summary>
    public abstract class AccessControlAuthority : IAccessControlAuthority, IAuthenticationSecretProvider, IAuthenticationTokenFactory, IPrincipalClaimProvider, IPrincipalRoleProvider, IAuthorizationEvaluatorFactory, IAccessPolicyEvaluationFactory
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessControlAuthority"/> class.
        /// </summary>
        /// <param name="name">The authority name.</param>
        /// <param name="itemValidator">The custom authentication item validator.</param>
        /// <param name="loggerFactory">The logger factory.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="name"/> is empty or only whitespace.</exception>
        protected AccessControlAuthority(string name, IAuthenticationItemValidator itemValidator, ILoggerFactory loggerFactory)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The authority name is empty or only whitespace.");

            Name = name;
            ItemValidator = itemValidator;
            LoggerFactory = loggerFactory;
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
        public IAuthenticationItemValidator ItemValidator { get; }

        /// <summary>
        /// Gets the logger factory.
        /// </summary>
        public ILoggerFactory LoggerFactory { get; }

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

            return new AuthenticationRequest(identity, Name, authenticationScheme);
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
        public async Task<string> CreateAuthenticationTokenAsync(AccessControlPrincipal principal, string authenticationScheme)
        {
            CheckAuthenticationScheme(authenticationScheme);

            var identity = principal.Identity;

            if (!identity.IsValid || !identity.IsAuthenticated)
                return string.Empty;

            var authenticationToken = new AuthenticationToken(identity, Name, authenticationScheme, principal.Claims, principal.Roles.Select(x => x.FullName));

            return await CreateAuthenticationTokenAsync(authenticationToken);
        }

        /// <summary>
        /// Creates <see cref="AuthenticationToken"/> from specified authentication token string.
        /// </summary>
        /// <param name="authenticationTokenString">The authentication token string.</param>
        /// <returns>A <see cref="AuthenticationToken"/>.</returns>
        public abstract Task<AuthenticationToken> CreateAuthenticationTokenAsync(string authenticationTokenString);

        /// <summary>
        /// Creates string value from specified authentication token.
        /// </summary>
        /// <param name="authenticationToken">The <see cref="AuthenticationToken"/>.</param>
        /// <returns>A authentication token string.</returns>
        protected abstract Task<string> CreateAuthenticationTokenAsync(AuthenticationToken authenticationToken);

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
        public Task<byte[]> GetAuthenticationSecretAsync(AccessControlIdentity identity, string authenticationScheme)
        {
            CheckAuthenticationScheme(authenticationScheme);

            return GetIdentityAuthenticationSecretAsync(identity, authenticationScheme);
        }

        /// <summary>
        /// Gets the secret of the specified identity for the specified authentication scheme.
        /// </summary>
        /// <param name="identity">The identity whose secret should be get.</param>
        /// <param name="authenticationScheme">The authentication scheme. The value depends on implementation.</param>
        /// <returns>A data of the secter or empty array if there is not such identity or if identity do not have secret in specified authentication scheme.</returns>
        /// <remarks><paramref name="authenticationScheme"/> is already validated to be one of the supported ones.</remarks>
        protected abstract Task<byte[]> GetIdentityAuthenticationSecretAsync(AccessControlIdentity identity, string authenticationScheme);

        /// <summary>
        /// Gets claims for specified principal if principal has valid authenticated identity.
        /// </summary>
        /// <param name="principal">The <see cref="AccessControlPrincipal"/>.</param>
        /// <returns>A claims of principal.</returns>
        public virtual Task<IEnumerable<AccessControlClaim>> GetPrincipalClaimsAsync(AccessControlPrincipal principal) => Task.FromResult(Enumerable.Empty<AccessControlClaim>());

        /// <summary>
        /// Gets roles assigned to specified principal if principal has valid authenticated identity.
        /// </summary>
        /// <param name="principal">The <see cref="AccessControlPrincipal"/>.</param>
        /// <returns>A roles assigned to principal.</returns>
        public virtual Task<IEnumerable<AccessControlRole>> GetPrincipalRolesAsync(AccessControlPrincipal principal) => Task.FromResult(Enumerable.Empty<AccessControlRole>());

        /// <summary>
        /// Gets the <see cref="IAuthorizationEvaluator"/> implementations. By default search implementations from assemblies of 
        /// current app domain and tries to create instance using parameterless constructor.
        /// </summary>
        /// <returns>A <see cref="IAuthorizationEvaluator"/> implementations.</returns>
        public virtual Task<IEnumerable<IAuthorizationEvaluator>> GetAuthorizationEvaluatorsAsync()
        {
            var evaluators = new List<IAuthorizationEvaluator>();

            foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
            {
                var interfaceTypes = assembly.GetTypes().Where(type => type.GetInterfaces().Any(x => x.Equals(typeof(IAuthorizationEvaluator))));

                foreach (var interfaceType in interfaceTypes)
                {
                    if (!interfaceType.IsConcrete())
                        continue;

                    var evaluator = TryCreateInstance<IAuthorizationEvaluator>(interfaceType);

                    if (evaluator != null)
                        evaluators.Add(evaluator);
                }
            }

            return Task.FromResult(evaluators.AsEnumerable());
        }

        /// <summary>
        /// Gets the <see cref="IAccessPolicyEvaluation"/> for specified access policy. By default search impelementations from assemblies of 
        /// current app domain and tries to create instance using parameterless constructor.
        /// </summary>
        /// <param name="policy">The <see cref="AccessPolicy"/>.</param>
        /// <returns>A <see cref="IAccessPolicyEvaluation"/> or <c>null</c>, if no evaluations for policy.</returns>
        public virtual Task<IAccessPolicyEvaluation?> GetAccessPolicyEvaluationAsync(AccessPolicy policy)
        {
            if (!policy.IsValid)
                throw new ArgumentException("The access policy is not valid.", nameof(policy));

            IAccessPolicyEvaluation? evaluation = null;

            // Policy not enabled, return null.
            if (!policy.IsEnabled)
                return Task.FromResult(evaluation);

            foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
            {
                var interfaceTypes = assembly.GetTypes().Where(type => type.GetInterfaces().Any(x => x.Equals(typeof(IAccessPolicyEvaluation))));

                foreach (var interfaceType in interfaceTypes)
                {
                    if (!interfaceType.IsConcrete())
                        continue;

                    var attributes = interfaceType.GetCustomAttributes<AccessPolicyAttribute>(false);

                    if (attributes.Any(attr => attr.PolicyName == policy.Name))
                    {
                        evaluation = TryCreateInstance<IAccessPolicyEvaluation>(interfaceType);

                        if (evaluation != null)
                            break;
                    }
                }

                if (evaluation != null)
                    break;
            }

            return Task.FromResult(evaluation);
        }

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

        protected static TInstance? TryCreateInstance<TInstance>(Type type) where TInstance : class
        {
            try
            {
                return Activator.CreateInstance(type) as TInstance;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
