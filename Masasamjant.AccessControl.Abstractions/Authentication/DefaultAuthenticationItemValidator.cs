namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Default impelementation of <see cref="IAuthenticationItemValidator"/> that just checks <see cref="IAuthenticationItem.IsValid"/> value.
    /// </summary>
    public sealed class DefaultAuthenticationItemValidator : IAuthenticationItemValidator
    {
        private readonly AuthenticationItemValidation validResult;
        private readonly AuthenticationItemValidation invalidResult;

        /// <summary>
        /// Initializes new default instance of the <see cref="DefaultAuthenticationItemValidator"/> class.
        /// </summary>
        public DefaultAuthenticationItemValidator()
            : this("Authentication item is not valid")
        { }

        /// <summary>
        /// Intializes new instance of the <see cref="DefaultAuthenticationItemValidator"/> class.
        /// </summary>
        /// <param name="invalidMessage">The invalid item message.</param>
        public DefaultAuthenticationItemValidator(string invalidMessage)
        {
            validResult = new AuthenticationItemValidation(true, null);
            invalidResult = new AuthenticationItemValidation(false, invalidMessage);
        }

        /// <summary>
        /// Validates <see cref="AuthenticationChallenge"/>.
        /// </summary>
        /// <param name="request">The authentication challenge.</param>
        /// <returns>A <see cref="AuthenticationItemValidation"/>.</returns>
        public AuthenticationItemValidation IsValidChallenge(AuthenticationChallenge challenge)
        {
            return challenge.IsValid ? validResult : invalidResult;    
        }

        /// <summary>
        /// Validates <see cref="AuthenticationRequest"/>.
        /// </summary>
        /// <param name="request">The authentication request.</param>
        /// <returns>A <see cref="AuthenticationItemValidation"/>.</returns>
        public AuthenticationItemValidation IsValidRequest(AuthenticationRequest request)
        {
            return request.IsValid ? validResult : invalidResult;
        }

        /// <summary>
        /// Validates <see cref="AuthenticationResponse"/>.
        /// </summary>
        /// <param name="request">The authentication response.</param>
        /// <returns>A <see cref="AuthenticationItemValidation"/>.</returns>
        public AuthenticationItemValidation IsValidResponse(AuthenticationResponse response)
        {
            return response.IsValid ? validResult : invalidResult;  
        }

        /// <summary>
        /// Validates <see cref="AuthenticationToken"/>.
        /// </summary>
        /// <param name="request">The authentication token.</param>
        /// <returns>A <see cref="AuthenticationItemValidation"/>.</returns>
        public AuthenticationItemValidation IsValidToken(AuthenticationToken token)
        {
            return token.IsValid ? validResult : invalidResult;
        }
    }
}
