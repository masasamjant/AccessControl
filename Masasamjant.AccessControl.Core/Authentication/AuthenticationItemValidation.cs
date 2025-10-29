namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents result of validation of <see cref="IAuthenticationItem"/>.
    /// </summary>
    public sealed class AuthenticationItemValidation
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthenticationItemValidation"/> class.
        /// </summary>
        /// <param name="valid"><c>true</c> if authentication item was valid; <c>false</c> otherwise.</param>
        /// <param name="unvalidReason">The reason why authentication item was invalid.</param>
        public AuthenticationItemValidation(bool valid, string? unvalidReason)
        {
            IsValid = valid;
            UnvalidReason = valid ? null : unvalidReason;
        }

        /// <summary>
        /// Gets if or not authentication item was valid.
        /// </summary>
        public bool IsValid { get; }

        /// <summary>
        /// Gets the reason why authentication item was invalid.
        /// </summary>
        public string? UnvalidReason { get; }
    }
}
