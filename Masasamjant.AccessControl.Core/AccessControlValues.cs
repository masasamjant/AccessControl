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
        /// Default name of local authority.
        /// </summary>
        public const string DefaultLocalAuthorityName = "LOCAL AUTHORITY";

        /// <summary>
        /// Default URI of local authority.
        /// </summary>
        public static readonly Uri DefaultLocalAuthorityUri = new Uri("/localhost", UriKind.Relative);

        /// <summary>
        /// Gets or sets item separator character. Default value is <see cref="DefaultItemSeparator"/>.
        /// </summary>
        public static char ItemSeparator { get; set; } = DefaultItemSeparator;

        /// <summary>
        /// Gets or sets the name of local authority. Default value is <see cref="DefaultLocalAuthorityName"/>.
        /// </summary>
        public static string LocalAuthorityName { get; set; } = DefaultLocalAuthorityName;

        /// <summary>
        /// Gets or sets the URI of local authority. Default value is "/localhost".
        /// </summary>
        public static Uri LocalAuthorityUri { get; set; } = DefaultLocalAuthorityUri;
    }
}
