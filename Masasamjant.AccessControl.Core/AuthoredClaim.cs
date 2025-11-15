using System.Security.Claims;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents a claim that has been authored by a specific authority.
    /// </summary>
    public sealed class AuthoredClaim : IAuthored, IEquatable<AuthoredClaim>
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthoredClaim"/> class.
        /// </summary>
        /// <param name="authority">The authority.</param>
        /// <param name="claimType">The claim type.</param>
        /// <param name="claimValue">The claim value.</param>
        /// <param name="claimValueType">The claim value type.</param>
        public AuthoredClaim(Authority authority, string claimType, string claimValue, string claimValueType)
        {
            Authority = authority;
            ClaimType = claimType;
            ClaimValue = claimValue;
            ClaimValueType = claimValueType;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AuthoredClaim"/> class that represents empty claim.
        /// </summary>
        public AuthoredClaim() 
        { }

        /// <summary>
        /// Gets the claim type.
        /// </summary>
        [JsonInclude]
        public string ClaimType { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets the claim value.
        /// </summary>
        [JsonInclude]
        public string ClaimValue { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets the claim value type.
        /// </summary>
        [JsonInclude]
        public string ClaimValueType { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets the authority.
        /// </summary>
        [JsonInclude]
        public Authority Authority { get; internal set; } = new Authority();

        /// <summary>
        /// Gets <see cref="Claim"/> create from this claim.
        /// </summary>
        /// <returns>A <see cref="Claim"/>.</returns>
        public Claim GetClaim()
        {
            return new Claim(ClaimType, ClaimValue, ClaimValueType, Authority.Uri.ToString());
        }

        /// <summary>
        /// Check if other <see cref="AuthoredClaim"/> is equal to this instance.
        /// </summary>
        /// <param name="other">The other <see cref="AuthoredClaim"/>.</param>
        /// <returns><c>true</c> if <paramref name="other"/> and this are equal; <c>false</c> otherwise.</returns>
        public bool Equals(AuthoredClaim? other)
        {
            return other != null &&
                   Authority.Equals(other.Authority) &&
                   ClaimType == other.ClaimType &&
                   ClaimValue == other.ClaimValue &&
                   ClaimValueType == other.ClaimValueType;
        }

        /// <summary>
        /// Check if object instance is <see cref="AuthoredClaim"/> and equal to this instance.
        /// </summary>
        /// <param name="obj">The object instance.</param>
        /// <returns><c>true</c> if <paramref name="obj"/> is <see cref="AuthoredClaim"/> and equal to this; <c>false</c> otherwise.</returns>
        public override bool Equals(object? obj)
        {
            return Equals(obj as AuthoredClaim);
        }

        /// <summary>
        /// Gets hash code.
        /// </summary>
        /// <returns>A hash code.</returns>
        public override int GetHashCode()
        {
            return HashCode.Combine(Authority, ClaimType, ClaimValue, ClaimValueType);
        }
    }
}
