using Masasamjant.AccessControl.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl
{
    public interface IAccessControlPrincipalProvider
    {
        IAccessControlPrincipal? GetAccessControlPrincipal(string name);

        IAccessControlPrincipal? GetAccessControlPrincipal(AuthenticationToken authenticationToken);

        string GetAuthenticationToken(IAccessControlPrincipal principal);
    }
}
