using Masasamjant.AccessControl.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization
{
    public sealed class Authorizer
    {
        public Authorizer(AccessControlAuthority authority, IAuthenticationTokenAuthenticator authenticator)
        {
            Authority = authority;
            Authenticator = authenticator;
        }

        private AccessControlAuthority Authority { get; }

        private IAuthenticationTokenAuthenticator Authenticator { get; }

        public AccessDecision Authorize(AccessRequest accessRequest)
        {
            throw new NotImplementedException();
        }

        public Task<AccessDecision> AuthorizeAsync(AccessRequest accessRequest) 
        {
            throw new NotImplementedException();
        }
    }
}
