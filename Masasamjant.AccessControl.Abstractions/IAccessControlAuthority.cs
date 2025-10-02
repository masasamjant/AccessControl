using Masasamjant.AccessControl.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl
{
    public interface IAccessControlAuthority : IAuthenticationSecretProvider, IAuthenticationTokenFactory, IPrincipalClaimProvider, IPrincipalRoleProvider
    {
        string Name { get; }

        AuthenticationRequest CreateAuthenticationRequest(AccessControlIdentity identity, string authenticationScheme);

        AccessControlIdentity GetAuthenticatedIdentity(AccessControlIdentity identity);

        bool IsAuthoring(IAuthenticationItem item);
        
        bool IsAuthoring(AccessControlIdentity identity);

        bool IsSupportedAuthentication(string authenticationScheme);
    }
}
