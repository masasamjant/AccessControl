namespace Masasamjant.AccessControl.Authorization.Policies
{
    /// <summary>
    /// Attribute to define what access policy implementation of <see cref="IAccessPolicyEvaluation"/> will evaluate.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = true, Inherited = false)]
    public sealed class AccessPolicyAttribute : Attribute
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessPolicyAttribute"/> class.
        /// </summary>
        /// <param name="policyName">The name of policy.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="policyName"/> is empty or only whitespace.</exception>
        /// <exception cref="ArgumentException">If value of <paramref name="policyName"/> contains character that is not whitespace, ASCII digit or unicode letter.</exception>
        public AccessPolicyAttribute(string policyName)
        {
            AccessPolicy.ValidatePolicyName(policyName);
            PolicyName = policyName;
        }

        /// <summary>
        /// Gets the name of policy.
        /// </summary>
        public string PolicyName { get; }
    }
}
