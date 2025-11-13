namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents a provider for user information.
    /// </summary>
    public interface IUserProvider : IUserSecretProvider
    {
        /// <summary>
        /// Gets the user by user name.
        /// </summary>
        /// <param name="userName">The user name.</param>
        /// <returns>A <see cref="IUser"/> or <c>null</c>, if not exist.</returns>
        /// <exception cref="ArgumentNullException">If value of <paramref name="userName"/> is empty or only whitespace.</exception>
        /// <exception cref="InvalidOperationException">If exception occurs while retrieving user.</exception>
        Task<IUser?> GetUserAsync(string userName);
    }
}
