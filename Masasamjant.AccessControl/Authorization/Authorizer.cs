using Masasamjant.AccessControl.Authentication;

namespace Masasamjant.AccessControl.Authorization
{
    public sealed class Authorizer : IAuthorizer
    {
        public Authorizer(IAccessControlAuthority authority)
        {
            Authority = authority;
            Authenticator = new AuthenticationTokenAuthenticator(Authority);
        }

        private IAccessControlAuthority Authority { get; }

        private AuthenticationTokenAuthenticator Authenticator { get; }

        public async Task<AccessDecision> AuthorizeAsync(AccessRequest accessRequest)
        {
            if (!accessRequest.IsValid)
                return AccessDecision.Denied(accessRequest);

            if (!accessRequest.Subject.Principal.Identity.IsAuthenticated || string.IsNullOrWhiteSpace(accessRequest.Subject.Principal.AuthenticationToken))
                return AccessDecision.Denied(accessRequest);

            var response = await Authenticator.AuthenticateTokenAsync(accessRequest.Subject.Principal.AuthenticationToken);

            if (response.Result == AuthenticationResult.Unauthenticated)
                return AccessDecision.Denied(accessRequest);

            var evaluators = await Authority.GetAuthorizationEvaluatorsAsync();

            if (!evaluators.Any())
                return AccessDecision.Denied(accessRequest);

            foreach (var evaluator in evaluators) 
            {
                var decision = await evaluator.EvaluateAsync(accessRequest);

                if (!decision.IsValid)
                    throw new InvalidOperationException($"Evaluator '{evaluator.GetType()}' returned invalid access decision.");

                if (decision.Result == AccessResult.Deny)
                    return AccessDecision.Denied(accessRequest);
            }

            return AccessDecision.Granted(accessRequest);
        }
    }
}
