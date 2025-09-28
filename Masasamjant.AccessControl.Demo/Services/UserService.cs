using Masasamjant.AccessControl.Authentication;
using Masasamjant.AccessControl.Demo.Models;
using Masasamjant.Security.Abstractions;
using System.Collections.Concurrent;
using System.Text;

namespace Masasamjant.AccessControl.Demo.Services
{
    public class UserService : IAccessControlPrincipalProvider, IAuthenticationSecretProvider
    {
        private IHashProvider hashProvider;
        private static ConcurrentBag<User> users = new ConcurrentBag<User>();

        public UserService(IHashProvider hashProvider)
        {
            this.hashProvider = hashProvider;
        }

        public User AddUser(string name, string password)
        {
            var userPassword = UserPassword.Create(name, password, hashProvider);
            var user = new User(name, userPassword.PasswordHash); //Convert.ToBase64String(hashProvider.ComputeHash(Encoding.Unicode.GetBytes(name + password))));
            users.Add(user);
            return user;
        }

        public User? GetUser(string name)
        {
            var user = users.Where(x => x.Name == name).FirstOrDefault();

            return user;
        }

        public byte[] GetAuthenticationSecret(string identity, string authenticationScheme)
        {
            if (authenticationScheme.ToUpperInvariant() != "PASSWORD")
                throw new NotSupportedException($"Authentication scheme '{authenticationScheme}' is not supported.");

            var user = GetUser(identity);
            return user != null ? Convert.FromBase64String(user.Password) : [];
        }

        public IAccessControlPrincipal? GetAccessControlPrincipal(string name)
        {
            return GetUser(name);
        }

        public IAccessControlPrincipal? GetAccessControlPrincipal(AuthenticationToken authenticationToken)
        {
            return GetAuthenticateUser(authenticationToken.Value);
        }

        public string GetAuthenticationToken(IAccessControlPrincipal principal)
        {
            if (principal is User user)
                return user.Identifier.ToString();
            return string.Empty;
        }

        private User? GetAuthenticateUser(string authenticationToken)
        {
            if (Guid.TryParse(authenticationToken, out var result))
            {
                return users.Where(x => x.Identifier == result).FirstOrDefault();
            }

            return null;
        }
    }
}
