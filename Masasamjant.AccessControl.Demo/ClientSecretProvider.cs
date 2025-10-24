using Masasamjant.AccessControl.Authentication;
using Masasamjant.AccessControl.Demo.Models;
using Masasamjant.AccessControl.Demo.Services;
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

        public Task<byte[]> GetAuthenticationSecretAsync(AccessControlIdentity identity, string authenticationScheme)
        {
            if (authenticationScheme.ToUpperInvariant() != DemoAuthority.AuthenticationScheme.ToUpperInvariant())
                throw new NotSupportedException($"Authentication scheme '{authenticationScheme}' is not supported.");

            var result = name == identity.Name ? secret : [];
            return Task.FromResult(result);
        }
    }
}
