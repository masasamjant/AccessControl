using System.Diagnostics.CodeAnalysis;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Provides helper methods to access control.
    /// </summary>
    public static class AccessControlHelper
    {
        /// <summary>
        /// Check if <see cref="AccessControlPrincipal"/> represents authenticated principal.
        /// </summary>
        /// <param name="principal">The <see cref="AccessControlPrincipal"/>.</param>
        /// <returns><c>true</c> if <paramref name="principal"/> represents valid and authenticated principal; <c>false</c> otherwise.</returns>
        /// <remarks>
        /// When returns <c>true</c>, then <paramref name="principal"/> is not <c>null</c>. Otherwise might be <c>null</c>.
        /// </remarks>
        public static bool IsAuthenticatePrincipal([NotNullWhen(true)] this AccessControlPrincipal? principal)
            => principal != null && principal.Identity.IsValid && principal.Identity.IsAuthenticated && !string.IsNullOrWhiteSpace(principal.AuthenticationToken); 
    }
}
