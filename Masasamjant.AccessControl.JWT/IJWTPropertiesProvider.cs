using System;
using System.Collections.Generic;
using System.Text;

namespace Masasamjant.AccessControl
{
    public interface IJWTPropertiesProvider
    {
        JWTProperties GetJWTProperties();
    }
}
