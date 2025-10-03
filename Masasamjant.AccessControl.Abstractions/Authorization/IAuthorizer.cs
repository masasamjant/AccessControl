using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization
{
    public interface IAuthorizer
    {
        Task<AccessDecision> AuthorizeAsync(AccessRequest accessRequest);
    }
}
