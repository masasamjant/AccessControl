namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents repository to store authentication requests.
    /// </summary>
    public interface IAuthenticationRequestRepository
    {
        /// <summary>
        /// Gets the <see cref="AuthenticationRequest"/> stored and removes it from storage if available.
        /// </summary>
        /// <param name="requestIdentifier">The authentication request identifier.</param>
        /// <returns>A <see cref="AuthenticationRequest"/> or <c>null</c>.</returns>
        Task<AuthenticationRequest?> GetAuthenticationRequestAsync(Guid requestIdentifier);

        /// <summary>
        /// Temporary store <see cref="AuthenticationRequest"/> during authentication process. 
        /// </summary>
        /// <param name="request">The <see cref="AuthenticationRequest"/> to store.</param>
        Task SaveAuthenticationRequestAsync(AuthenticationRequest request);
    }
}
