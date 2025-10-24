using Masasamjant.AccessControl.Web.Authentication;
using Masasamjant.AccessControl.Web.Authorization;

namespace Masasamjant.AccessControl.Web
{
    /// <summary>
    /// Provides helper methods to register required services.
    /// </summary>
    public static class ServiceCollectionHelper
    {
        /// <summary>
        /// Register <see cref="AccessControlPrincipalStore"/> using <see cref="DefaultAccessControlPrincipalStore"/>.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="accessControlPrincipalKey">The key to store principal in HTTP context items.</param>
        /// <returns>A service collection.</returns>
        public static IServiceCollection AddAccessControlPrincipalStore(this IServiceCollection services, string accessControlPrincipalKey)
            => services.AddAccessControlPrincipalStore(new DefaultAccessControlPrincipalStore(accessControlPrincipalKey));

        /// <summary>
        /// Register specified <see cref="AccessControlPrincipalStore"/> as singleton instance.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="singleton">The <see cref="AccessControlPrincipalStore"/> singleton instance.</param>
        /// <returns>A service collection.</returns>
        public static IServiceCollection AddAccessControlPrincipalStore(this IServiceCollection services, AccessControlPrincipalStore singleton)
            => services.AddSingleton(singleton);

        /// <summary>
        /// Register <typeparamref name="TStore"/> as scoped <see cref="AccessControlPrincipalStore"/>.
        /// </summary>
        /// <typeparam name="TStore">The type of the store.</typeparam>
        /// <param name="services">The service collection.</param>
        /// <returns>A service collection.</returns>
        public static IServiceCollection AddAccessControlPrincipalStore<TStore>(this IServiceCollection services) where TStore : AccessControlPrincipalStore
            => services.AddScoped<AccessControlPrincipalStore, TStore>();

        /// <summary>
        /// Register <typeparamref name="TProvider"/> as scoped <see cref="IAuthenticationMiddlewareContextProvider"/>.
        /// </summary>
        /// <typeparam name="TProvider">The type of the provider.</typeparam>
        /// <param name="services">The service collection.</param>
        /// <returns>A service collection.</returns>
        public static IServiceCollection AddAuthenticationContextProvider<TProvider>(this IServiceCollection services) where TProvider : class, IAuthenticationMiddlewareContextProvider
            => services.AddScoped<IAuthenticationMiddlewareContextProvider, TProvider>();

        /// <summary>
        /// Register specified <see cref="IAuthenticationMiddlewareContextProvider"/> as singleton instance.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="singleton">The <see cref="IAuthenticationMiddlewareContextProvider"/> singleton instance.</param>
        /// <returns>A service collection.</returns>
        public static IServiceCollection AddAuthenticationContextProvider(this IServiceCollection services, IAuthenticationMiddlewareContextProvider singleton)
            => services.AddSingleton(singleton);

        /// <summary>
        /// Register <see cref="DefaultAuthenticationMiddlewareContextProvider"/> as singleton <see cref="IAuthenticationMiddlewareContextProvider"/>.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <returns>A service collection.</returns>
        public static IServiceCollection AddAuthenticationContextProvider(this IServiceCollection services)
            => services.AddAuthenticationContextProvider<DefaultAuthenticationMiddlewareContextProvider>();

        /// <summary>
        /// Register <typeparamref name="TProvider"/> as scoped <see cref="IAuthorizationMiddlewareContextProvider"/>.
        /// </summary>
        /// <typeparam name="TProvider">The type of the provider.</typeparam>
        /// <param name="services">The service collection.</param>
        /// <returns>A service collection.</returns>
        public static IServiceCollection AddAuthorizationContextProvider<TProvider>(this IServiceCollection services) where TProvider : class, IAuthorizationMiddlewareContextProvider
            => services.AddScoped<IAuthorizationMiddlewareContextProvider, TProvider>();

        /// <summary>
        /// Register specified <see cref="IAuthorizationMiddlewareContextProvider"/> as singleton instance.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="singleton">The <see cref="IAuthorizationMiddlewareContextProvider"/> singleton instance.</param>
        /// <returns>A service collection.</returns>
        public static IServiceCollection AddAuthorizationContextProvider(this IServiceCollection services, IAuthorizationMiddlewareContextProvider singleton)
            => services.AddSingleton(singleton);

        /// <summary>
        /// Register <see cref="DefaultAuthorizationMiddlewareContextProvider"/> as singleton <see cref="IAuthorizationMiddlewareContextProvider"/>.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <returns>A service collection.</returns>
        public static IServiceCollection AddAuthorizationContextProvider(this IServiceCollection services)
            => services.AddAuthorizationContextProvider<DefaultAuthorizationMiddlewareContextProvider>();

        /// <summary>
        /// Register <typeparamref name="TProvider"/> as scoped <see cref="IAccessControlUrlProvider"/>.
        /// </summary>
        /// <typeparam name="TProvider">The type of the provider.</typeparam>
        /// <param name="services">The service collection.</param>
        /// <returns>A service collection.</returns>
        public static IServiceCollection AddAccessControlUrlProvider<TProvider>(this IServiceCollection services) where TProvider : class, IAccessControlUrlProvider
            => services.AddScoped<IAccessControlUrlProvider, TProvider>();

        /// <summary>
        /// Register specified <see cref="IAccessControlUrlProvider"/> as singleton instance.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="singleton">The <see cref="IAccessControlUrlProvider"/> singleton instance.</param>
        /// <returns>A service collection.</returns>
        public static IServiceCollection AddAccessControlUrlProvider(this IServiceCollection services, IAccessControlUrlProvider singleton)
            => services.AddSingleton(singleton);

        /// <summary>
        /// Register <see cref="DefaultAccessControlUrlProvider"/> as singleton <see cref="IAccessControlUrlProvider"/> using specified URLs.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="accessDeniedUrl">The access denied URL or <c>null</c>.</param>
        /// <param name="loginUrl">The login URL or <c>null</c>.</param>
        /// <param name="unauthenticatedUrl">The unauthenticated URL or <c>null</c>.</param>
        /// <returns>A service collection.</returns>
        public static IServiceCollection AddAccessControlUrlProvider(this IServiceCollection services, string? accessDeniedUrl, string? loginUrl, string? unauthenticatedUrl)
            => services.AddAccessControlUrlProvider(new DefaultAccessControlUrlProvider(accessDeniedUrl, loginUrl, unauthenticatedUrl));
    }
}
