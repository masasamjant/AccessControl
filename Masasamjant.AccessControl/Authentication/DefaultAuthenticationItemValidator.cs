namespace Masasamjant.AccessControl.Authentication
{
    internal sealed class DefaultAuthenticationItemValidator : IAuthenticationItemValidator
    {
        private readonly AuthenticationItemValidation validResult = new AuthenticationItemValidation(true, null);
        private readonly AuthenticationItemValidation invalidResult = new AuthenticationItemValidation(false, "Authentication item is not valid");

        public AuthenticationItemValidation IsValidChallenge(AuthenticationChallenge challenge)
        {
            return challenge.IsValid ? validResult : invalidResult;    
        }

        public AuthenticationItemValidation IsValidRequest(AuthenticationRequest request)
        {
            return request.IsValid ? validResult : invalidResult;
        }

        public AuthenticationItemValidation IsValidResponse(AuthenticationResponse response)
        {
            return response.IsValid ? validResult : invalidResult;  
        }

        public AuthenticationItemValidation IsValidToken(AuthenticationToken token)
        {
            return token.IsValid ? validResult : invalidResult;
        }
    }
}
