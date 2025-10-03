namespace Masasamjant.AccessControl.Authorization
{
    /// <summary>
    /// Authorization evaluator that perform access decision evaluation for access request.
    /// </summary>
    public interface IAuthorizationEvaluator
    {
        /// <summary>
        /// Evaluates access request and returns access decision based on evaluation.
        /// </summary>
        /// <param name="request">The <see cref="AccessRequest"/> to evaluate</param>
        /// <returns>A <see cref="AccessDecision"/>.</returns>
        Task<AccessDecision> EvaluateAsync(AccessRequest request);
    }
}
