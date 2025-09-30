using Masasamjant.AccessControl.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization
{
    public abstract class AccessControlList
    {
        public abstract AccessResult? GetAccessResult(AccessRequest accessRequest);

        public abstract void SetAccessResult(AccessDecision accessDecision);

        public abstract void Clear();
    }
}
