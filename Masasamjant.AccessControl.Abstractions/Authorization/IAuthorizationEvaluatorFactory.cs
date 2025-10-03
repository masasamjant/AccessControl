namespace Masasamjant.AccessControl.Authorization
{
    /// <summary>
    /// Factory to get <see cref="IAuthorizationEvaluator"/> implementations.
    /// </summary>
    public interface IAuthorizationEvaluatorFactory
    {
        /// <summary>
        /// Gets the <see cref="IAuthorizationEvaluator"/> implementations.
        /// </summary>
        /// <returns>A <see cref="IAuthorizationEvaluator"/> implementations.</returns>
        Task<IEnumerable<IAuthorizationEvaluator>> GetAuthorizationEvaluatorsAsync();
    }
}
