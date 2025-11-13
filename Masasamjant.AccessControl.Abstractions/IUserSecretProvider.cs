namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents a provider for user secrets.
    /// </summary>
    public interface IUserSecretProvider
    {
        /// <summary>
        /// Gets the user secret for the specified user and secret type.
        /// </summary>
        /// <param name="userName">The user name.</param>
        /// <param name="secretType">The secret type.</param>
        /// <returns>A <see cref="IUserSecret"/> or <c>null</c>, if user not exist or user do not have secret of specified type.</returns>
        /// <exception cref="ArgumentNullException">If value of <paramref name="userName"/> is empty or only whitespace.</exception>
        /// <exception cref="ArgumentException">If value of <paramref name="secretType"/> is not defined in <see cref="UserSecretType"/>.</exception>
        Task<IUserSecret?> GetUserSecretAsync(string userName, UserSecretType secretType);
    }
}
