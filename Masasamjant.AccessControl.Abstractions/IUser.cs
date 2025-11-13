namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents a user.
    /// </summary>
    public interface IUser
    {
        /// <summary>
        /// Gets the unique user name.
        /// </summary>
        string UserName { get; }

        /// <summary>
        /// Gets the email address associated with user or empty string.
        /// </summary>
        string EmailAddress { get; }

        /// <summary>
        /// Gets the mobile phone number associated with user or empty string.
        /// </summary>
        string MobilePhone { get; }

        /// <summary>
        /// Gets the name of roles assigned to user.
        /// </summary>
        IEnumerable<string> Roles { get; }

        /// <summary>
        /// Gets the unique identifier of the user.
        /// </summary>
        /// <returns>A unique identifier or <c>null</c>.</returns>
        string? GetIdentifier();
    }
}
