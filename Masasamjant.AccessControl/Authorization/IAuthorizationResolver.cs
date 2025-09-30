using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization
{
    /// <summary>
    /// Represents <see cref="IAuthorization"/> that resolves the <see cref="AccessDecision"/>. This is the abstraction over the final
    /// access control pattern used by application.
    /// </summary>
    public interface IAuthorizationResolver : IAuthorization
    {
        event EventHandler<InvalidateAccessObjectEventArgs>? InvalidateAuthorization;
    }
}
