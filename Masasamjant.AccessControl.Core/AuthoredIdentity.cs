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
        private List<AuthoredRole> roles = new List<AuthoredRole>();

        /// <summary>
        /// Initializes new instance of the <see cref="AuthoredIdentity"/> with specified name.
        /// </summary>
        /// <param name="authority">The authority.</param>
        /// <param name="name">The identity name.</param>
        /// <param name="properties">The identity properties.</param>
        public AuthoredIdentity(Authority authority, string name, IUser? user)
            : this()
        {
            Authority = authority;
            AddAuthoredClaim(ClaimTypes.Name, name, ClaimValueTypes.String);

            if (user != null)
            {
                AddAuthoredClaim(ClaimTypes.Authentication, bool.TrueString, ClaimValueTypes.Boolean);
                AddAuthoredClaim(ClaimTypes.AuthenticationInstant, authority.Uri.ToString(), ClaimValueTypes.String);

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
                AddAuthoredClaim(ClaimTypes.Authentication, bool.FalseString, ClaimValueTypes.Boolean);
            }
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AuthoredIdentity"/> class.
        /// </summary>
        public AuthoredIdentity()
        { }

        [JsonInclude]
        public Authority Authority { get; internal set; } = new Authority();

        [JsonInclude]
        public IReadOnlyCollection<AuthoredClaim> AuthoredClaims
        {
            get { return claims.AsReadOnly(); }
            internal set { claims = value.ToList(); }
        }

        [JsonInclude]
        public IReadOnlyCollection<AuthoredRole> Roles
        {
            get { return roles.AsReadOnly(); }
            internal set { roles = value.ToList(); }
        }

        [JsonIgnore]
        public override IEnumerable<Claim> Claims
        {
            get
            {
                foreach (var claim in claims)
                    yield return claim.GetClaim();
            }
        }

        [JsonIgnore]
        public override bool IsAuthenticated
        {
            get 
            {
                var claim = claims.FirstOrDefault(c => c.ClaimType == ClaimTypes.Authentication);
                return claim != null && claim.ClaimValue == bool.TrueString;
            }
        }

        [JsonIgnore]
        public new string Name
        {
            get { return base.Name ?? string.Empty; }
        }

        public override void AddClaim(Claim claim)
        {
            throw new NotSupportedException("Adding claim is not supported.");
        }

        public override void AddClaims(IEnumerable<Claim?> claims)
        {
            throw new NotSupportedException("Adding claims is not supported.");
        }

        private void AddAuthoredClaim(string claimType, string claimValue, string claimValueType)
        {
            claims.Add(new AuthoredClaim(Authority, claimType, claimValue, claimValueType));
        }
    }
}
