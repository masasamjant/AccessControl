using Masasamjant.AccessControl.Authentication;
using System.Text;
using System.Text.Json;

namespace Masasamjant.AccessControl.Demo.Services
{
    public class DemoAuthority : AccessControlAuthority
    {
        internal const string AuthenticationScheme = "PASSWORD";

        private readonly IAuthenticationSecretProvider secretProvider;
        private readonly IUserService userService;
        public DemoAuthority(IUserService userService, IAuthenticationSecretProvider secretProvider, IAuthenticationItemValidator itemValidator)
            : base("Demo", itemValidator)
        {
            this.userService = userService;
            this.secretProvider = secretProvider;
        }

        protected override string[] AuthenticationSchemes => [AuthenticationScheme];


        public override async Task<AuthenticationToken> CreateAuthenticationTokenAsync(string authenticationTokenString)
        {
            if (string.IsNullOrWhiteSpace(authenticationTokenString))
                return new AuthenticationToken();

            try
            {
                var stream = new MemoryStream(authenticationTokenString.GetByteArray(Encoding.UTF8));
                var authenticationToken = await JsonSerializer.DeserializeAsync<AuthenticationToken>(stream);

                // No valid token or token not authorized by this authority > return invalid token.
                if (authenticationToken == null || !IsAuthoring(authenticationToken))
                    return new AuthenticationToken();

                return authenticationToken;
            }
            catch (Exception)
            {
                return new AuthenticationToken();
            }
        }

        public override AccessControlIdentity GetAuthenticatedIdentity(AccessControlIdentity identity)
        {
            return new DemoAccessControlIdentity(identity, AuthenticationScheme);
        }

        public override bool IsAuthoring(AccessControlIdentity identity)
        {
            var user = userService.GetUser(identity.Name);
            return user != null;
        }

        protected override async Task<string> CreateAuthenticationTokenAsync(AuthenticationToken authenticationToken)
        {
            var stream = new MemoryStream();
            await JsonSerializer.SerializeAsync(stream, authenticationToken);
            var buffer = stream.ToArray();
            return Encoding.UTF8.GetString(buffer);
        }

        protected override Task<byte[]> GetIdentityAuthenticationSecretAsync(AccessControlIdentity identity, string authenticationScheme)
        {
            return secretProvider.GetAuthenticationSecretAsync(identity, authenticationScheme);
        }

        private class DemoAccessControlIdentity : AccessControlIdentity
        {
            public DemoAccessControlIdentity(AccessControlIdentity identity, string authenticationScheme)
                : base(identity.Name, true, authenticationScheme)
            {
                if (!identity.IsValid)
                    throw new ArgumentException("The identity is not valid.", nameof(identity));
            }
        }
    }
}
