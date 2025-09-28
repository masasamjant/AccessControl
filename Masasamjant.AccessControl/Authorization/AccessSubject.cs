using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization
{
    public class AccessSubject
    {
        [JsonInclude]
        public string Identity { get; internal set; } = string.Empty;
    }
}
