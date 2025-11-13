using Masasamjant.AccessControl.Authentication;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace Masasamjant.AccessControl
{
    public class JWTAuthenticationTokenBuilder : IAuthenticationTokenBuilder
    {
        private readonly IJWTPropertiesProvider propertiesProvider;

        public JWTAuthenticationTokenBuilder(IJWTPropertiesProvider propertiesProvider)
        {
            this.propertiesProvider = propertiesProvider;
        }

        public Task<string> BuildAuthenticationTokenAsync(AuthenticationToken token)
        {
            string tokenString = string.Empty;

            if (token.IsAuthenticated)
            {
                var properties = propertiesProvider.GetJWTProperties();
                var signKey = Encoding.UTF8.GetBytes(properties.SignKey);
                var symmetricKey = new SymmetricSecurityKey(signKey);
                var credentials = new SigningCredentials(symmetricKey, properties.SignAlgorithm);
                var claims = token.Identity.Claims.ToList();
                var securityToken = new JwtSecurityToken(token.Authority.Name, token.Authority.Name, claims, expires: DateTime.Now.AddHours(2), signingCredentials: credentials);
                tokenString = new JwtSecurityTokenHandler().WriteToken(securityToken);
            }

            return Task.FromResult(tokenString);
        }

        public Task<AuthenticationToken?> BuildAuthenticationTokenAsync(string token, Authority authority)
        {
            AuthenticationToken? authenticationToken = null;

            if (!string.IsNullOrWhiteSpace(token))
            {
                try
                {
                    var securityToken = new JwtSecurityToken(token);
                    
                    if (securityToken.Issuer == authority.Name &&
                        securityToken.Audiences.Any(aud => aud == authority.Name))
                    {
                        var claims = securityToken.Claims.ToList();
                    }
                }
                catch (Exception exception)
                {
                    authenticationToken = null;
                }
            }

            return Task.FromResult(authenticationToken);
        }
    }
}
