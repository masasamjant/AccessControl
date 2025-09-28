using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization
{
    public class AccessResponse
    {
        public AccessRequest Request { get; internal set; } = new AccessRequest();

        public AccessResult Result { get; internal set; }
    }
}
