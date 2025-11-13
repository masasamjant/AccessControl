using System;
using System.Collections.Generic;
using System.Text;

namespace Masasamjant.AccessControl.Authentication
{
    public interface IAuthenticationTokenAuthenticator
    {
        Task<AuthenticationResultResponse> AuthenticateTokenAsync(string authenticationToken);
    }
}
