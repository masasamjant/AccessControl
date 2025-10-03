using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization.Policies
{
    public class AccessPolicy
    {
        public AccessPolicy(string name, AccessObject accessObject, bool enabled)
        {
            Name = name;
            Object = accessObject;
            IsEnabled = enabled;
        }

        public string Name { get; internal set; }

        public AccessObject Object { get; internal set; }

        public bool IsEnabled { get; internal set; }
    }
}
