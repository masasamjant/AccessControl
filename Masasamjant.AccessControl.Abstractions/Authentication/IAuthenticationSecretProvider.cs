namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents provider of identity secret of the specified authentication scheme.
    /// </summary>
    public interface IAuthenticationSecretProvider
    {
        /// <summary>
        /// Gets the secret of the specified identity for the specified authentication scheme.
        /// </summary>
        /// <param name="identity">The identity whose secret should be get.</param>
        /// <param name="authenticationScheme">The authentication scheme. The value depends on implementation.</param>
        /// <returns>A data of the secter or empty array if there is not such identity or if identity do not have secret in specified authentication scheme.</returns>
        /// <exception cref="ArgumentNullException">If value of <paramref name="authenticationScheme"/> is empty or only whitespace.</exception>
        /// <exception cref="NotSupportedException">If authentication scheme specified by <paramref name="authenticationScheme"/> is not supported.</exception>
        Task<byte[]> GetAuthenticationSecretAsync(AccessControlIdentity identity, string authenticationScheme);
    }
}
