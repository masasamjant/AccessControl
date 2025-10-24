namespace Masasamjant.AccessControl.Web.Authentication
{
    /// <summary>
    /// Attribute applied to class to indicate access control authentication use.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
    public sealed class AccessControlAuthenticationAttribute : Attribute
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessControlAuthenticationAttribute"/> class.
        /// </summary>
        /// <param name="redirectUrl">The unauthenticated redirect URL or <c>null</c>.</param>
        public AccessControlAuthenticationAttribute(string? redirectUrl = null)
        {
            RedirectUrl = string.IsNullOrWhiteSpace(redirectUrl) ? null : redirectUrl;
        }

        /// <summary>
        /// Gets the unauthenticated redirect URL or <c>null</c>.
        /// </summary>
        public string? RedirectUrl { get; }
    }
}
