using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl
{
    public interface IUserProvider : IUserSecretProvider
    {
        Task<IUser?> GetUserAsync(string userName);
    }
}
