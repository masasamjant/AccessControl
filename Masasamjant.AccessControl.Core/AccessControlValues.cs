namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Defines known values used by access control.
    /// </summary>
    public static class AccessControlValues
    {
        /// <summary>
        /// Default value of <see cref="ItemSeparator"/>.
        /// </summary>
        public const char DefaultItemSeparator = '|';

        /// <summary>
        /// Gets or sets item separator character. Default value is <see cref="DefaultItemSeparator"/>.
        /// </summary>
        public static char ItemSeparator { get; set; } = DefaultItemSeparator;
    }
}
