using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl
{
    public interface IUserSecretProvider
    {
        Task<IUserSecret?> GetUserSecretAsync(string userName, UserSecretType secretType);
    }
}
