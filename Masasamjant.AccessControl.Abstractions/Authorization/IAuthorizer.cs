namespace Masasamjant.AccessControl.Authorization
{
    /// <summary>
    /// Represents service to authorize access request.
    /// </summary>
    public interface IAuthorizer
    {
        /// <summary>
        /// Authorizes specified access request.
        /// </summary>
        /// <param name="accessRequest">The access request.</param>
        /// <returns>A access decision.</returns>
        Task<AccessDecision> AuthorizeAsync(AccessRequest accessRequest);
    }
}
