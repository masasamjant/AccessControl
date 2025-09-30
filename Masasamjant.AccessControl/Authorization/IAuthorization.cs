using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization
{
    public interface IAuthorization
    {
        AccessDecision Authorize(AccessRequest request);
    }
}
