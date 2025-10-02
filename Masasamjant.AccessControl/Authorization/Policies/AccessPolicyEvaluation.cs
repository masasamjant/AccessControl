using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization.Policies
{
    /// <summary>
    /// Represent class that evaluated <see cref="AccessPolicy"/>.
    /// </summary>
    public abstract class AccessPolicyEvaluation
    {
        public abstract bool CanEvaluate(AccessPolicy policy);
        public abstract AccessDecision Evaluate(AccessPolicy policy, AccessControlIdentity identity);
    }
}
