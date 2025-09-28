using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization
{
    /// <summary>
    /// Represents result of the access decision.
    /// </summary>
    public enum AccessResult : int
    {
        /// <summary>
        /// Access is denied.
        /// </summary>
        Deny = 0,

        /// <summary>
        /// Access is granted.
        /// </summary>
        Grant = 1
    }
}
