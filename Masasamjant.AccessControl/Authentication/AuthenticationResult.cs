namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Defines results of authentication.
    /// </summary>
    public enum AuthenticationResult : int
    {
        /// <summary>
        /// Unauthenticated.
        /// </summary>
        Unauthenticated = 0,

        /// <summary>
        /// Authenticated.
        /// </summary>
        Authenticated = 1
    }
}
