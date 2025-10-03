using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization.Policies
{
    public abstract class PolicyAuthorizationEvaluator : AuthorizationEvaluator
    {
        protected readonly IAccessPolicyEvaluationFactory evaluationFactory;

        protected PolicyAuthorizationEvaluator(IAccessPolicyEvaluationFactory evaluationFactory)
        {
            this.evaluationFactory = evaluationFactory;
        }

        protected override async Task<AccessDecision> EvaluateRequestAsync(AccessRequest request)
        {
            var policies = await GetObjectPoliciesAsync(request.Object);

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

        protected abstract Task<IEnumerable<AccessPolicy>> GetObjectPoliciesAsync(AccessObject obj);
    }
}
