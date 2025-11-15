using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Factory to create JWT token validation parameters.
    /// </summary>
    public static class JwtTokenValidationParametersFactory
    {
        /// <summary>
        /// Creates token validation parameters based on the provided JWT token properties.
        /// </summary>
        /// <param name="properties">The JWT token properties.</param>
        /// <returns>A <see cref="TokenValidationParameters"/>.</returns>
        public static TokenValidationParameters CreateTokenValidationParameters(JwtTokenProperties properties)
        {
            var audience = string.IsNullOrWhiteSpace(properties.Audience) ? properties.Authority.Name : properties.Audience;

            var validationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidIssuer = properties.Authority.GetIssuerString(),
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateIssuerSigningKey = properties.IsSigned,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            if (properties.IsSigned)
            { 
                var signKey = Encoding.UTF8.GetBytes(properties.SignKey);
                var symmetricKey = new SymmetricSecurityKey(signKey);
                validationParameters.IssuerSigningKey = symmetricKey;
            }
        
            if (properties.IsEncrypted)
            {
                var encKey = Encoding.UTF8.GetBytes(properties.EncryptKey);
                var encSymmetricKey = new SymmetricSecurityKey(encKey);
                validationParameters.TokenDecryptionKey = encSymmetricKey;
            };

            return validationParameters;
        }
    }
}
