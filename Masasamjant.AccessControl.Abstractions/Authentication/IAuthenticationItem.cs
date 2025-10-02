namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authentication item.
    /// </summary>
    public interface IAuthenticationItem
    {
        /// <summary>
        /// Gets the unique identifier.
        /// </summary>
        Guid Identifier { get; }

        /// <summary>
        /// Gets the UTC date and time when created.
        /// </summary>
        DateTimeOffset Created { get; }

        /// <summary>
        /// Gets the name of authority associated with this item.
        /// </summary>
        string Authority { get; }

        /// <summary>
        /// Gets if or not is valid.
        /// </summary>
        bool IsValid { get; }
    }
}
