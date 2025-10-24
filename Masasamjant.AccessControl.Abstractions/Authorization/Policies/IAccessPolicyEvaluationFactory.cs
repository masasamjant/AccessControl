namespace Masasamjant.AccessControl.Authorization.Policies
{
    /// <summary>
    /// Factory to create instance of <see cref="IAccessPolicyEvaluation"/> for specified access policy.
    /// </summary>
    public interface IAccessPolicyEvaluationFactory
    {
        /// <summary>
        /// Gets the <see cref="IAccessPolicyEvaluation"/> for specified access policy.
        /// </summary>
        /// <param name="policy">The <see cref="AccessPolicy"/>.</param>
        /// <returns>A <see cref="IAccessPolicyEvaluation"/> or <c>null</c>, if no evaluations for policy or if policy is not enabled.</returns>
        /// <exception cref="ArgumentException">If <paramref name="policy"/> is not valid.</exception>
        Task<IAccessPolicyEvaluation?> GetAccessPolicyEvaluationAsync(AccessPolicy policy);
    }
}
