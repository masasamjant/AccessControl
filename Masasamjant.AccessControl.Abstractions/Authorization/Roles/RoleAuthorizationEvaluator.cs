namespace Masasamjant.AccessControl.Authorization.Roles
{
    /// <summary>
    /// Represents abstract <see cref="AuthorizationEvaluator"/> that evaluates role based authorization.
    /// </summary>
    public abstract class RoleAuthorizationEvaluator : AuthorizationEvaluator
    {
        /// <summary>
        /// Evaluates access request and returns access decision based on evaluation.
        /// Before invoking this it is ensured that <paramref name="request"/> is valid and subject principal is authenticated.
        /// </summary>
        /// <param name="request">The <see cref="AccessRequest"/> to evaluate</param>
        /// <returns>A <see cref="AccessDecision"/>.</returns>
        protected override async Task<AccessDecision> EvaluateRequestAsync(AccessRequest request)
        {
            var principalRoles = request.Subject.Principal.Roles;

            // If principal does not have any roles, then return denied.
            if (!principalRoles.Any())
                return AccessDecision.Denied(request);

            var objectRoles = (await GetObjectRolesAsync(request.Object)).Where(role => !role.IsEmpty);

            // If the object does not have any roles, then return denied.
            if (!objectRoles.Any())
                return AccessDecision.Denied(request);

            var conditionRoles = new List<AccessRole>();

            foreach (var objectRole in objectRoles)
                if (principalRoles.Any(role => role.Equals(objectRole)))
                    conditionRoles.Add(objectRole);

            // If the principal does not have any of the object roles, then return denied.
            if (conditionRoles.Count == 0)
                return AccessDecision.Denied(request);

            // If any of the object roles deny access, then return denied.
            foreach (var conditionRole in conditionRoles)
                if (conditionRole.Result == AccessResult.Deny)
                    return AccessDecision.Denied(request);

            // Otherwise access is granted.
            return AccessDecision.Granted(request);
        }

        /// <summary>
        /// Gets the access roles of the specified access object. If any of returned roles deny access, then access is denied. 
        /// Otherwise access is granted.
        /// </summary>
        /// <param name="accessObject">The <see cref="AccessObject"/>.</param>
        /// <returns>A roles that have access or no access to specified object, if empty then access is denied.</returns>
        protected abstract Task<IEnumerable<AccessRole>> GetObjectRolesAsync(AccessObject accessObject);
    }
}
