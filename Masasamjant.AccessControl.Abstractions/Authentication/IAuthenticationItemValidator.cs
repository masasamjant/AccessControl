namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents validator to validate different authentication items.
    /// </summary>
    public interface IAuthenticationItemValidator
    {
        /// <summary>
        /// Validates <see cref="AuthenticationRequest"/>.
        /// </summary>
        /// <param name="request">The authentication request.</param>
        /// <returns>A <see cref="AuthenticationItemValidation"/>.</returns>
        AuthenticationItemValidation IsValidRequest(AuthenticationRequest request);

        /// <summary>
        /// Validates <see cref="AuthenticationChallenge"/>.
        /// </summary>
        /// <param name="request">The authentication challenge.</param>
        /// <returns>A <see cref="AuthenticationItemValidation"/>.</returns>
        AuthenticationItemValidation IsValidChallenge(AuthenticationChallenge challenge);

        /// <summary>
        /// Validates <see cref="AuthenticationToken"/>.
        /// </summary>
        /// <param name="request">The authentication token.</param>
        /// <returns>A <see cref="AuthenticationItemValidation"/>.</returns>
        AuthenticationItemValidation IsValidToken(AuthenticationToken token);

        /// <summary>
        /// Validates <see cref="AuthenticationResponse"/>.
        /// </summary>
        /// <param name="request">The authentication response.</param>
        /// <returns>A <see cref="AuthenticationItemValidation"/>.</returns>
        AuthenticationItemValidation IsValidResponse(AuthenticationResponse response);
    }
}
