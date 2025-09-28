namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents exception thrown if <see cref="IAuthenticationItem"/> is not valid or if authentication process fails.
    /// </summary>
    public class AuthenticationException : Exception
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationException"/> class.
        /// </summary>
        /// <param name="item">The <see cref="IAuthenticationItem"/> associated with exception.</param>
        public AuthenticationException(IAuthenticationItem item)
            : this($"Unexpected error when using authentication item of '{item.GetType()}'.", item)
        { }

        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationException"/> class.
        /// </summary>
        /// <param name="message">The exception message.</param>
        /// <param name="item">The <see cref="IAuthenticationItem"/> associated with exception.</param>
        public AuthenticationException(string message, IAuthenticationItem item)
            : this(message, item, null)
        { }

        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationException"/> class.
        /// </summary>
        /// <param name="message">The exception message.</param>
        /// <param name="item">The <see cref="IAuthenticationItem"/> associated with exception.</param>
        /// <param name="innerException">The inner exception.</param>
        public AuthenticationException(string message, IAuthenticationItem item, Exception? innerException)
            : base(message, innerException)
        {
            AuthenticationItem = item;
        }

        /// <summary>
        /// Gets the <see cref="IAuthenticationItem"/> associate with exception.
        /// </summary>
        public IAuthenticationItem AuthenticationItem { get; }
    }
}
