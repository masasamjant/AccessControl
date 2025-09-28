using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization
{
    public class AccessRequest
    {
        public AccessSubject Subject { get; internal set; } = new AccessSubject();

        public AccessObject Object { get; internal set; } = new AccessObject();

        public AccessType AccessType { get; internal set; }

        
    }
}
