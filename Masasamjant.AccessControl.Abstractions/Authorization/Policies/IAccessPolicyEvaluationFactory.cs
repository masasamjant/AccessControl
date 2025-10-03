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
        /// <returns>A <see cref="IAccessPolicyEvaluation"/> or <c>null</c>, if no evaluations for policy.</returns>
        Task<IAccessPolicyEvaluation?> GetAccessPolicyEvaluationAsync(AccessPolicy policy);
    }
}
