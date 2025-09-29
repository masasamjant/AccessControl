using Masasamjant.AccessControl.Authentication;
using System.Text.Json;

namespace Masasamjant.AccessControl.Demo.Services
{
    public class DemoAuthority : AccessControlAuthority
    {
        internal const string AuthenticationScheme = "PASSWORD";

        private readonly IAccessControlPrincipalProvider principalProvider;
        private readonly IAuthenticationSecretProvider secretProvider;

        public DemoAuthority(IAccessControlPrincipalProvider principalProvider, IAuthenticationSecretProvider secretProvider)
            : base("Demo")
        {
            this.principalProvider = principalProvider;
            this.secretProvider = secretProvider;
        }

        protected override string[] AuthenticationSchemes => [AuthenticationScheme];

        public override IAccessControlPrincipal? GetAccessControlPrincipal(string name)
        {
            return principalProvider.GetAccessControlPrincipal(name);
        }

        public override AuthenticationToken GetAuthenticationToken(string authenticationTokenString)
        {
            if (string.IsNullOrWhiteSpace(authenticationTokenString))
                return new AuthenticationToken();

            try
            {
                var authenticationToken = JsonSerializer.Deserialize<AuthenticationToken>(authenticationTokenString);

                // No valid token or token not authorized by this authority > return invalid token.
                if (authenticationToken == null || !IsAuthorized(authenticationToken))
                    return new AuthenticationToken();

                return authenticationToken;
            }
            catch (Exception)
            {
                return new AuthenticationToken();
            }
        }

        protected override string CreateAuthenticationToken(AuthenticationToken authenticationToken)
        {
            return JsonSerializer.Serialize(authenticationToken);
        }

        protected override byte[] GetIdentityAuthenticationSecret(string identity, string authenticationScheme)
        {
            return secretProvider.GetAuthenticationSecret(identity, authenticationScheme);
        }
    }
}
