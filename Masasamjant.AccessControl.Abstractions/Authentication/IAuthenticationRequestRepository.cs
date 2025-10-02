namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents repository that store <see cref="AuthenticationRequest"/>.
    /// </summary>
    public interface IAuthenticationRequestRepository
    {
        /// <summary>
        /// Gets the saved <see cref="AuthenticationRequest"/> from repository and removes it.
        /// </summary>
        /// <param name="identifier">The authentication request identifier.</param>
        /// <returns>A <see cref="AuthenticationRequest"/> or <c>null</c>, if not exist.</returns>
        AuthenticationRequest? GetAuthenticationRequest(Guid identifier);

        /// <summary>
        /// Saves authentication request.
        /// </summary>
        /// <param name="request">The <see cref="AuthenticationRequest"/> to save.</param>
        void SaveAuthenticationRequest(AuthenticationRequest request);
    }
}
