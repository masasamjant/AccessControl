using Masasamjant.AccessControl.Authentication;
using Masasamjant.AccessControl.Demo.Models;
using Masasamjant.Security.Abstractions;

namespace Masasamjant.AccessControl.Demo
{
    public class ClientSecretProvider : IAuthenticationSecretProvider
    {
        private readonly byte[] secret;
        private readonly string name;

        public ClientSecretProvider(string name, string password, IHashProvider hashProvider)
        {
            this.name = name;
            var userPassword = UserPassword.Create(name, password, hashProvider);
            this.secret = userPassword.PasswordData;
        }

        public byte[] GetAuthenticationSecret(string identity, string authenticationScheme)
        {
            if (authenticationScheme.ToUpperInvariant() != "PASSWORD")
                throw new NotSupportedException($"Authentication scheme '{authenticationScheme}' is not supported.");

            if (name != identity)
                return [];

            return secret;
            throw new NotImplementedException();
        }
    }
}
