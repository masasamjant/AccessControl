using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authentication
{
    public interface IAuthenticationItemValidator
    {
        AuthenticationItemValidation IsValidRequest(AuthenticationRequest request);

        AuthenticationItemValidation IsValidChallenge(AuthenticationChallenge challenge);

        AuthenticationItemValidation IsValidToken(AuthenticationToken token);

        AuthenticationItemValidation IsValidResponse(AuthenticationResponse response);
    }
}
