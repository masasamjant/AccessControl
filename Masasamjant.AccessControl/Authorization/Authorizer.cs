using Masasamjant.AccessControl.Authentication;

namespace Masasamjant.AccessControl.Authorization
{
    /// <summary>
    /// Represents service to authorize access request.
    /// </summary>
    public sealed class Authorizer : IAuthorizer
    {
        /// <summary>
        /// Initializes new instance of the <see cref="Authorizer"/> class.
        /// </summary>
        /// <param name="authority">The <see cref="IAccessControlAuthority"/>.</param>
        public Authorizer(IAccessControlAuthority authority)
        {
            Authority = authority;
        }

        private IAccessControlAuthority Authority { get; }

        /// <summary>
        /// Authorizes specified access request.
        /// </summary>
        /// <param name="accessRequest">The access request.</param>
        /// <returns>A access decision.</returns>
        public async Task<AccessDecision> AuthorizeAsync(AccessRequest accessRequest)
        {
            // If request is not valid, then denied.
            if (!accessRequest.IsValid)
                return AccessDecision.Denied(accessRequest);

            // If principal not authenticated, then denied.
            if (!accessRequest.Subject.Principal.IsAuthenticatePrincipal())
                return AccessDecision.Denied(accessRequest);

            // Get authorization evaluators.
            var evaluators = await Authority.GetAuthorizationEvaluatorsAsync();

            // If not any evaluators, then denied.
            if (!evaluators.Any())
                return AccessDecision.Denied(accessRequest);

            // Check with each evaluator if any denies, then denied.
            foreach (var evaluator in evaluators) 
            {
                var decision = await evaluator.EvaluateAsync(accessRequest);

                if (!decision.IsValid)
                    throw new InvalidOperationException($"Evaluator '{evaluator.GetType()}' returned invalid access decision.");

                if (decision.Result == AccessResult.Deny)
                    return AccessDecision.Denied(accessRequest);
            }

            // All evaluators granted access.
            return AccessDecision.Granted(accessRequest);
        }
    }
}
