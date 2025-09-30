using Masasamjant.AccessControl.Demo.Services;
using System.Security.Claims;
using System.Security.Principal;

namespace Masasamjant.AccessControl.Demo.Models
{
    public class User
    {
        public User(string name, string password)
        {
            Identifier = Guid.NewGuid();
            Name = name;
            Password = password;
        }

        public Guid Identifier { get; private set; }

        public string Name { get; private set; }
        
        public string Password { get; private set; }
    }
}
