namespace Masasamjant.AccessControl.Authorization
{
    /// <summary>
    /// Represents abstract authorization evaluator that perform access decision evaluation for access request.  
    /// </summary>
    public abstract class AuthorizationEvaluator : IAuthorizationEvaluator
    {
        /// <summary>
        /// Evaluates access request and returns access decision based on evaluation.
        /// </summary>
        /// <param name="request">The <see cref="AccessRequest"/> to evaluate</param>
        /// <returns>A <see cref="AccessDecision"/>.</returns>
        public async Task<AccessDecision> EvaluateAsync(AccessRequest request)
        {
            if (!request.IsValid)
                return AccessDecision.Denied(request);

            if (!request.Subject.Principal.Identity.IsAuthenticated)
                return AccessDecision.Denied(request);

            return await EvaluateRequestAsync(request);
        }

        /// <summary>
        /// Evaluates access request and returns access decision based on evaluation.
        /// Before invoking this it is ensured that <paramref name="request"/> is valid and subject principal is authenticated.
        /// </summary>
        /// <param name="request">The <see cref="AccessRequest"/> to evaluate</param>
        /// <returns>A <see cref="AccessDecision"/>.</returns>
        protected abstract Task<AccessDecision> EvaluateRequestAsync(AccessRequest request); 
    }
}
