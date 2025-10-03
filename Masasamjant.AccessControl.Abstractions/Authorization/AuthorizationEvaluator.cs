using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization
{
    public abstract class AuthorizationEvaluator : IAuthorizationEvaluator
    {
        public async Task<AccessDecision> EvaluateAsync(AccessRequest request)
        {
            if (!request.IsValid)
                return AccessDecision.Denied(request);

            if (!request.Subject.Principal.Identity.IsAuthenticated)
                return AccessDecision.Denied(request);

            return await EvaluateRequestAsync(request);
        }

        protected abstract Task<AccessDecision> EvaluateRequestAsync(AccessRequest request); 
    }
}
