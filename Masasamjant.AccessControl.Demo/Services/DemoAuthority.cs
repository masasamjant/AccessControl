using Masasamjant.AccessControl.Authentication;
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


        public override AuthenticationToken CreateAuthenticationToken(string authenticationTokenString)
        {
            if (string.IsNullOrWhiteSpace(authenticationTokenString))
                return new AuthenticationToken();

            try
            {
                var authenticationToken = JsonSerializer.Deserialize<AuthenticationToken>(authenticationTokenString);

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

        protected override string CreateAuthenticationToken(AuthenticationToken authenticationToken)
        {
            return JsonSerializer.Serialize(authenticationToken);
        }

        protected override byte[] GetIdentityAuthenticationSecret(string identity, string authenticationScheme)
        {
            return secretProvider.GetAuthenticationSecret(identity, authenticationScheme);
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
