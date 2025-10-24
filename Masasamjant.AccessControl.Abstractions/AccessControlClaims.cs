namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Defines access control claims.
    /// </summary>
    public static class AccessControlClaims
    {
        /// <summary>
        /// Name of authority claim.
        /// </summary>
        public const string Authority = "http://masasamjant/accesscontrol/authority";

        /// <summary>
        /// Name of authentication token claim.
        /// </summary>
        public const string AuthenticationToken = "http://masasamjant/accesscontrol/auth/token";

        /// <summary>
        /// Name of authentication scheme claim.
        /// </summary>
        public const string AuthenticationScheme = "http://masasamjant/accesscontrol/auth/scheme";

        /// <summary>
        /// Name of identity name claim.
        /// </summary>
        public const string IdentityName = "http://masasamjant/accesscontrol/identity/name";

        /// <summary>
        /// Name of identity roles claim.
        /// </summary>
        public const string Roles = "http://masasamjant/accesscontrol/identity/roles";

        private static readonly HashSet<string> knownClaims = new HashSet<string>()
        {
            Authority, AuthenticationToken, IdentityName, Roles, AuthenticationScheme
        };

        /// <summary>
        /// Check is claims specified by name reserved.
        /// </summary>
        /// <param name="name">The name of claim.</param>
        /// <returns><c>true</c> if name is reserved for claim; <c>false</c> otherwise.</returns>
        public static bool IsReservedClaim(string name) => knownClaims.Contains(name);
    }
}
