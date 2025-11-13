namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents authored item.
    /// </summary>
    public interface IAuthored
    {
        /// <summary>
        /// Gets the authority.
        /// </summary>
        Authority Authority { get; }
    }
}
