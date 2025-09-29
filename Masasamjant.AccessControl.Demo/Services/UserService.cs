using Masasamjant.AccessControl.Authentication;
using Masasamjant.AccessControl.Demo.Models;
using Masasamjant.Security.Abstractions;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;

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
            var user = new User(name, userPassword.PasswordHash);
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
            var user = GetUser(identity);
            return user != null ? Convert.FromBase64String(user.Password) : [];
        }

        public IAccessControlPrincipal? GetAccessControlPrincipal(string name)
        {
            return GetUser(name);
        }
    }
}
