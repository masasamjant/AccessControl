namespace Masasamjant.AccessControl.Authorization
{
    /// <summary>
    /// Defines access types.
    /// </summary>
    public enum AccessType : int
    {
        /// <summary>
        /// View or see access.
        /// </summary>
        View = 0,

        /// <summary>
        /// Add or insert access.
        /// </summary>
        Add = 1,

        /// <summary>
        /// Update or modify access.
        /// </summary>
        Update = 2,

        /// <summary>
        /// Delete or remove access.
        /// </summary>
        Delete = 3
    }
}
