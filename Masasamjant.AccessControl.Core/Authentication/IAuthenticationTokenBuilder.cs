using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authentication
{
    public interface IAuthenticationTokenBuilder
    {
        Task<string> BuildAuthenticationTokenAsync(AuthenticationToken token);

        Task<AuthenticationToken?> BuildAuthenticationTokenAsync(string token, Authority authority);
    }
}
