namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents authenticator that authenticates challenges.
    /// </summary>
    public interface IAuthenticationChallengeAuthenticator
    {
        AuthenticationRequestResponse RequestAuthentication(AuthenticationRequest request);

        AuthenticationResultResponse AuthenticateChallenge(AuthenticationChallenge challenge);
    }
}
