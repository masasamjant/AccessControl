using System.Security.Claims;
using System.Security.Principal;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents authored <see cref="ClaimsIdentity"/>.
    /// </summary>
    public class AuthoredIdentity : ClaimsIdentity, IAuthored, IIdentity
    {
        private List<AuthoredClaim> claims = new List<AuthoredClaim>();
        private List<AuthoredRole>? roles;
        private Authority? authority;

        /// <summary>
        /// Initializes new instance of the <see cref="AuthoredIdentity"/> with specified name.
        /// </summary>
        /// <param name="authority">The authority.</param>
        /// <param name="name">The identity name.</param>
        /// <param name="properties">The identity properties.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="name"/> is empty or only whitespace.</exception>
        public AuthoredIdentity(Authority authority, string name, IUser? user)
            : this()
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The name is empty or only whitespace.");

            AddAuthoredClaim(ClaimTypes.System, string.Join(AccessControlValues.ItemSeparator, Authority.Uri, Authority.Name), ClaimValueTypes.String);
            AddAuthoredClaim(ClaimTypes.Name, name, ClaimValueTypes.String);

            if (user != null)
            {
                AddAuthoredClaim(ClaimTypes.Authentication, bool.TrueString.ToLowerInvariant(), ClaimValueTypes.String);
                AddAuthoredClaim(ClaimTypes.AuthenticationInstant, authority.Uri.ToString(), ClaimValueTypes.String);

                var roles = user.Roles.ToList();

                if (roles.Count > 0)
                    AddAuthoredClaim(ClaimTypes.Role, string.Join(AccessControlValues.ItemSeparator, roles.Select(AuthoredRole.IsValidRoleName)), ClaimValueTypes.String);

                var identifier = user.GetIdentifier();
                if (!string.IsNullOrWhiteSpace(identifier))
                    AddAuthoredClaim(ClaimTypes.NameIdentifier, identifier, ClaimValueTypes.String);

                if (!string.IsNullOrWhiteSpace(user.EmailAddress))
                    AddAuthoredClaim(ClaimTypes.Email, user.EmailAddress, ClaimValueTypes.Email);

                if (!string.IsNullOrWhiteSpace(user.MobilePhone))
                    AddAuthoredClaim(ClaimTypes.MobilePhone, user.MobilePhone, ClaimValueTypes.String);
            }
            else
            {
                AddAuthoredClaim(ClaimTypes.Authentication, bool.FalseString.ToLowerInvariant(), ClaimValueTypes.Boolean);
            }
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AuthoredIdentity"/> class.
        /// </summary>
        public AuthoredIdentity()
        { }

        private AuthoredIdentity(IEnumerable<AuthoredClaim> claims)
        {
            this.claims = claims.ToList();
        }

        /// <summary>
        /// Gets the authority.
        /// </summary>
        [JsonIgnore]
        public Authority Authority
        {
            get
            {
                if (authority == null)
                    authority = GetAuthority();

                return authority;
            }
        }

        /// <summary>
        /// Gets the claims associated with identity.
        /// </summary>
        [JsonInclude]
        public IReadOnlyCollection<AuthoredClaim> AuthoredClaims
        {
            get { return claims.AsReadOnly(); }
            internal set { claims = value.ToList(); }
        }

        /// <summary>
        /// Gets the roles associated with identity.
        /// </summary>
        [JsonIgnore]
        public IReadOnlyCollection<AuthoredRole> Roles
        {
            get
            {
                if (roles == null)
                {
                    roles = new List<AuthoredRole>();
                    FillRoles(roles);
                }

                return roles.AsReadOnly();
            }
        }

        /// <summary>
        /// Gets if or not represents authenticated identity.
        /// </summary>
        [JsonIgnore]
        public override bool IsAuthenticated
        {
            get 
            {
                var claim = claims.FirstOrDefault(c => c.ClaimType == ClaimTypes.Authentication);
                return claim != null && claim.ClaimValue.ToLowerInvariant() == bool.TrueString.ToLowerInvariant();
            }
        }

        /// <summary>
        /// Gets <see cref="AuthoredClaims"/> converted to claims of <see cref="Claim"/>.
        /// </summary>
        [JsonIgnore]
        public override IEnumerable<Claim> Claims => GetSystemClaims();

        /// <summary>
        /// Gets the name of identity.
        /// </summary>
        [JsonIgnore]
        public new string Name
        {
            get { return base.Name ?? string.Empty; }
        }

        /// <summary>
        /// Adding claim is not supported.
        /// </summary>
        /// <param name="claim">The claim to add.</param>
        /// <exception cref="NotSupportedException">Always.</exception>
        public override void AddClaim(Claim claim)
        {
            throw new NotSupportedException("Adding claim is not supported.");
        }

        /// <summary>
        /// Adding claims is not supported.
        /// </summary>
        /// <param name="claims">The claims to add.</param>
        /// <exception cref="NotSupportedException">Always.</exception>
        public override void AddClaims(IEnumerable<Claim?> claims)
        {
            throw new NotSupportedException("Adding claims is not supported.");
        }

        /// <summary>
        /// Removing claim is not supported.    
        /// </summary>
        /// <param name="claim">The claim to remove.</param>
        /// <exception cref="NotSupportedException">Always.</exception>
        public override void RemoveClaim(Claim? claim)
        {
            throw new NotSupportedException("Removing claim is not supported.");
        }

        /// <summary>
        /// Removing claim is not supported.
        /// </summary>
        /// <param name="claim">The claim to remove.</param>
        /// <exception cref="NotSupportedException">Always.</exception>
        public override bool TryRemoveClaim(Claim? claim)
        {
            throw new NotSupportedException("Removing claim is not supported.");
        }

        /// <summary>
        /// Creates copy from current instance.
        /// </summary>
        /// <returns>A <see cref="AuthoredIdentity"/> that is copy from this instance.</returns>
        public override ClaimsIdentity Clone()
        {
            return new AuthoredIdentity(AuthoredClaims);
        }

        internal IEnumerable<Claim> GetSystemClaims()
        {
            foreach (var claim in claims)
                yield return claim.GetClaim();
        }

        private void AddAuthoredClaim(string claimType, string claimValue, string claimValueType)
        {
            claims.Add(new AuthoredClaim(Authority, claimType, claimValue, claimValueType));
        }

        private void FillRoles(List<AuthoredRole> list)
        {
            var claim = claims.FirstOrDefault(c => c.ClaimType == ClaimTypes.Role);

            if (claim == null || string.IsNullOrWhiteSpace(claim.ClaimValue))
                return;

            var roles = claim.ClaimValue.Split(AccessControlValues.ItemSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            foreach (var role in roles)
            {
                if (!string.IsNullOrWhiteSpace(role))
                    list.Add(new AuthoredRole(Authority, role));
            }
        }

        private Authority GetAuthority()
        {
            var claim = claims.FirstOrDefault(c => c.ClaimType == ClaimTypes.System);

            if (claim == null || string.IsNullOrWhiteSpace(claim.ClaimValue))
                return new Authority();

            var parts = claim.ClaimValue.Split(AccessControlValues.ItemSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            if (parts.Length != 2 || string.IsNullOrWhiteSpace(parts[0]) || string.IsNullOrWhiteSpace(parts[1]))
                return new Authority();

            if (Uri.TryCreate(parts[0], UriKind.RelativeOrAbsolute, out var uri))
                return new Authority(uri, parts[1]);

            return new Authority();
        }
    }
}
