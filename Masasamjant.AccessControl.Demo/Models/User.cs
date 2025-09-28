using Masasamjant.AccessControl.Authentication;

namespace Masasamjant.AccessControl.Demo.Models
{
    public class User : IAccessControlPrincipal, IAccessControlIdentity
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

        public IAccessControlIdentity GetAccessControlIdentity()
        {
            return this;
        }

        public IEnumerable<AccessControlClaim> GetClaims()
        {
            var claims = new AccessControlClaim[]
            {
                    new AccessControlClaim(nameof(Identifier), Identifier.ToString()),
                    new AccessControlClaim(nameof(Name), Name)
            };

            return claims;
        }
    }
}
