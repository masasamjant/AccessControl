using Masasamjant.AccessControl.Authentication;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace Masasamjant.AccessControl
{
    public class JwtAuthenticationTokenBuilder : AuthenticationTokenBuilder
    {
        private readonly IJwtTokenPropertiesProvider propertiesProvider;
        private readonly JwtSecurityTokenHandler handler;

        public JwtAuthenticationTokenBuilder(IJwtTokenPropertiesProvider propertiesProvider)
        {
            this.propertiesProvider = propertiesProvider;
            this.handler = new JwtSecurityTokenHandler();
        }

        public override Task<string> BuildAuthenticationTokenAsync(AuthenticationToken token)
        {
            string tokenString = string.Empty;

            if (token.IsAuthenticated)
            {
                var now = DateTime.Now;
                var properties = propertiesProvider.GetJWTProperties(token.Authority).Clone();
                if (token.Authority.IsAuthoring(properties))
                    throw new InvalidOperationException("Provider returned properties for invalid authority.");
                var claims = token.Identity.Claims.ToList();
                var audience = string.IsNullOrWhiteSpace(properties.Audience) ? token.Authority.Name : properties.Audience;
                var issuer = token.Authority.GetIssuerString();

                JwtSecurityToken securityToken;

                SigningCredentials? signingCredentials = null;

                if (properties.IsSigned)
                {
                    var signKey = properties.SignKey.GetByteArray(properties.KeyEncoding);
                    var symmetricKey = new SymmetricSecurityKey(signKey);
                    signingCredentials = new SigningCredentials(symmetricKey, properties.SignAlgorithm.ToAlgorithmString());
                }

                if (properties.IsEncrypted)
                {
                    var encKey = properties.EncryptKey.GetByteArray(properties.KeyEncoding);
                    var encSymmetricKey = new SymmetricSecurityKey(encKey);
                    var encCredentials = new EncryptingCredentials(encSymmetricKey, properties.EncryptKeyWrapAlgorithm.ToAlgorithmString(), properties.EncryptAlgorithm.ToAlgorithmString());
                    securityToken = handler.CreateJwtSecurityToken(issuer, audience, token.Identity, now, now.AddMinutes(properties.TokenExpiryInMinutes), now, signingCredentials, encCredentials);
                }
                else
                { 
                    securityToken = handler.CreateJwtSecurityToken(
                        issuer: issuer,
                        audience: audience,
                        subject: new System.Security.Claims.ClaimsIdentity(claims),
                        notBefore: now,
                        expires: now.AddMinutes(properties.TokenExpiryInMinutes),
                        issuedAt: now,
                        signingCredentials: signingCredentials);
                }

                tokenString = handler.WriteToken(securityToken);
            }

            return Task.FromResult(tokenString);
        }

        public override Task<AuthenticationToken?> BuildAuthenticationTokenAsync(string token, Authority authority)
        {
            AuthenticationToken? authenticationToken = null;

            if (!string.IsNullOrWhiteSpace(token))
                return Task.FromResult(authenticationToken);

            try
            {
                var securityToken = GetValidatedToken(token, authority); new JwtSecurityToken(token);

                if (securityToken == null)
                    return Task.FromResult(authenticationToken);

                var claims = securityToken.Claims.ToList();
                var identity = CreateAuthoredIdentity(claims);

                if (authority.IsAuthoring(identity) && identity.IsAuthenticated)
                {
                    authenticationToken = new AuthenticationToken(identity);
                }

                return Task.FromResult(authenticationToken);
            }
            catch (Exception exception)
            {
                throw new AuthenticationException("Failed to build authentication token from provided authentication token string. See inner exception.", exception);
            }   
        }

        private JwtSecurityToken? GetValidatedToken(string token, Authority authority) 
        {
            try
            {
                var properties = propertiesProvider.GetJWTProperties(authority).Clone();
                var validationParameters = JwtTokenValidationParametersFactory.CreateTokenValidationParameters(properties);
                handler.ValidateToken(token, validationParameters, out var validatedToken);
                return validatedToken as JwtSecurityToken;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
