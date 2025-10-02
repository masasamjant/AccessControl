using Masasamjant.AccessControl.Authentication;

namespace Masasamjant.AccessControl.Demo.Services
{
    public class DemoAuthenticationItemValidator : IAuthenticationItemValidator
    {
        public AuthenticationItemValidation IsValidChallenge(AuthenticationChallenge challenge)
        {
            if (HasValidCreationTime(challenge.Created))
                return new AuthenticationItemValidation(true, null);
            else
                return new AuthenticationItemValidation(false, "Authentication challenge is expired.");
        }

        public AuthenticationItemValidation IsValidRequest(AuthenticationRequest request)
        {
            if (HasValidCreationTime(request.Created))
                return new AuthenticationItemValidation(true, null);
            else
                return new AuthenticationItemValidation(false, "Authentication request is expired.");
        }

        public AuthenticationItemValidation IsValidResponse(AuthenticationResponse response)
        {
            if (HasValidCreationTime(response.Created))
                return new AuthenticationItemValidation(true, null);
            else
                return new AuthenticationItemValidation(false, "Authentication response is expired.");
        }

        public AuthenticationItemValidation IsValidToken(AuthenticationToken token)
        {
            if (HasValidCreationTime(token.Created))
                return new AuthenticationItemValidation(true, null);
            else
                return new AuthenticationItemValidation(false, "Authentication token is expired.");
        }

        private static bool HasValidCreationTime(DateTimeOffset value)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;

            if (value > now)
                return false;

            if (now.Subtract(value).TotalSeconds > TimeSpan.FromMinutes(5).TotalSeconds)
                return false;

            return true;
        }
    }
}
