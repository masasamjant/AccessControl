namespace Masasamjant.AccessControl.Authorization.Policies
{
    /// <summary>
    /// Access policy evaluation that evaluates access policy for specified access control identity.
    /// </summary>
    public interface IAccessPolicyEvaluation
    {
        /// <summary>
        /// Check if can evaluate specified access policy.
        /// </summary>
        /// <param name="policy">The access policy to evaluate.</param>
        /// <returns><c>true</c> if can evaluate <paramref name="policy"/>; <c>false</c> otherwise.</returns>
        Task<bool> CanEvaluateAsync(AccessPolicy policy);

        /// <summary>
        /// Evaluates access policy againts specified identity.
        /// </summary>
        /// <param name="policy">The access policy to evaluate.</param>
        /// <param name="identity">The access control identity to evaluate policy against with.</param>
        /// <returns>A <see cref="AccessResult"/> of policy evaluation.</returns>
        Task<AccessResult> EvaluateAsync(AccessPolicy policy, AccessControlIdentity identity);
    }
}
