using System.Security.Claims;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents authored <see cref="ClaimsPrincipal"/>.
    /// </summary>
    public sealed class AuthoredPrincipal : ClaimsPrincipal, IAuthored
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthoredPrincipal"/> class with specified <see cref="AuthoredIdentity"/>.
        /// </summary>
        /// <param name="identity">The <see cref="AuthoredIdentity"/> associated with principal.</param>
        public AuthoredPrincipal(AuthoredIdentity identity)
            : base(identity)
        {
            Authority = identity.Authority;
            Identity = identity;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AuthoredPrincipal"/> class.
        /// </summary>
        public AuthoredPrincipal() 
        { }

        private AuthoredPrincipal(Authority authority, AuthoredIdentity identity)
        {
            Authority = authority;
            Identity = identity;
        }

        /// <summary>
        /// Gets the authority.
        /// </summary>
        [JsonInclude]
        public Authority Authority { get; internal set; } = new Authority();

        /// <summary>
        /// Gets the authored identity. 
        /// </summary>
        [JsonInclude]
        public new AuthoredIdentity Identity { get; internal set; } = new AuthoredIdentity();

        /// <summary>
        /// Gets claims of the identity.
        /// </summary>
        [JsonIgnore]
        public override IEnumerable<Claim> Claims => Identity.GetSystemClaims();

        /// <summary>
        /// Gets the identities.
        /// </summary>
        [JsonIgnore]
        public override IEnumerable<ClaimsIdentity> Identities
        {
            get { return [Identity]; }
        }

        /// <summary>
        /// Adding identities is not supported.
        /// </summary>
        /// <param name="identities">The identities.</param>
        /// <exception cref="NotSupportedException">Always.</exception>
        public override void AddIdentities(IEnumerable<ClaimsIdentity> identities)
        {
            throw new NotSupportedException("Adding identities is not supported.");
        }

        /// <summary>
        /// Adding identity is not supported.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <exception cref="NotSupportedException">Always.</exception>
        public override void AddIdentity(ClaimsIdentity identity)
        {
            throw new NotSupportedException("Adding identity is not supported.");
        }

        /// <summary>
        /// Creates copy from current instance.
        /// </summary>
        /// <returns>A <see cref="AuthoredPrincipal"/> that is copy from this instance.</returns>
        public override ClaimsPrincipal Clone()
        {
            var identity = (AuthoredIdentity)Identity.Clone();
            return new AuthoredPrincipal(Authority, identity);
        }

        /// <summary>
        /// Check if identity has specified role.
        /// </summary>
        /// <param name="role">The role.</param>
        /// <returns><c>true</c> if has role; <c>false</c> otherwise.</returns>
        public override bool IsInRole(string role)
        {
            return Identity.Roles.Any(x => x.Name == role);
        }
    }
}
