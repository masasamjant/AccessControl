namespace Masasamjant.AccessControl.Authorization.Policies
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = false)]
    public sealed class AccessPolicyAttribute : Attribute
    {
        public AccessPolicyAttribute(string policyName)
        {
            if (string.IsNullOrWhiteSpace(policyName))
                throw new ArgumentNullException(nameof(policyName), "The policy name is empty or only whitespace.");

            PolicyName = policyName;
        }

        public string PolicyName { get; }
    }
}
