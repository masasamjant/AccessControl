namespace Masasamjant.AccessControl.Authorization.Policies
{
    /// <summary>
    /// Represents abstract authorization evaluator that perform access decision evaluation for access request 
    /// based on access policies associated with object.
    /// </summary>
    public abstract class PolicyAuthorizationEvaluator : AuthorizationEvaluator
    {
        protected readonly IAccessPolicyEvaluationFactory evaluationFactory;

        /// <summary>
        /// Initializes new instance of the <see cref="PolicyAuthorizationEvaluator"/> class.
        /// </summary>
        /// <param name="evaluationFactory">The <see cref="IAccessPolicyEvaluationFactory"/>.</param>
        protected PolicyAuthorizationEvaluator(IAccessPolicyEvaluationFactory evaluationFactory)
        {
            this.evaluationFactory = evaluationFactory;
        }

        /// <summary>
        /// Evaluates access request and returns access decision based on evaluation.
        /// Before invoking this it is ensured that <paramref name="request"/> is valid and subject principal is authenticated.
        /// </summary>
        /// <param name="request">The <see cref="AccessRequest"/> to evaluate</param>
        /// <returns>A <see cref="AccessDecision"/>.</returns>
        protected override async Task<AccessDecision> EvaluateRequestAsync(AccessRequest request)
        {
            // Get valid and enabled policies.
            var policies = (await GetObjectPoliciesAsync(request.Object))
                .Where(p => p.IsValid && p.IsEnabled).ToList();

            // If there is not any policies, then return granted.
            if (!policies.Any())
                return AccessDecision.Granted(request);

            foreach (var policy in policies)
            {
                var evaluation = await evaluationFactory.GetAccessPolicyEvaluationAsync(policy);

                // No evaluation or cannot evaluate, continue to next one.
                if (evaluation == null || !await evaluation.CanEvaluateAsync(policy))
                    continue;

                // Evaluate policy for current identity.
                var result = await evaluation.EvaluateAsync(policy, request.Subject.Principal.Identity);

                // If result of policy is to deny, then return denied.
                if (result == AccessResult.Deny)
                    return AccessDecision.Denied(request);
            }

            // No policy to deny, then return granted.
            return AccessDecision.Granted(request);
        }

        /// <summary>
        /// Gets the access policies for the specified access object.
        /// </summary>
        /// <param name="obj">The access object.</param>
        /// <returns>A access policies associated with object.</returns>
        protected abstract Task<IEnumerable<AccessPolicy>> GetObjectPoliciesAsync(AccessObject obj);
    }
}
