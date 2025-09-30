using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization
{
    public class InvalidateAccessObjectEventArgs : EventArgs
    {
        public InvalidateAccessObjectEventArgs(AccessObject accessObject)
        {
            if (!accessObject.IsValid)
                throw new ArgumentException("The access object is not valid.", nameof(accessObject));

            Object = accessObject;
        }

        public AccessObject Object { get; }
    }
}
