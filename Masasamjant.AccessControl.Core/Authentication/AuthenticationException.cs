namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Exception thrown if authentication process fails.
    /// </summary>
    public class AuthenticationException : Exception
    {
        /// <summary>
        /// Initializes new default instance of the <see cref="AuthenticationException"/> class.
        /// </summary>
        public AuthenticationException()
            : this("An unexpected authentication error occurred.")
        { }

        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationException"/> class.
        /// </summary>
        /// <param name="message">The exception message.</param>
        public AuthenticationException(string message)
            : this(message, null)
        { }

        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationException"/> class.
        /// </summary>
        /// <param name="message">The exception message.</param>
        /// <param name="innerException">The inner exception or <c>null</c>.</param>
        public AuthenticationException(string message, Exception? innerException)
            : base(message, innerException)
        { }
    }
}
