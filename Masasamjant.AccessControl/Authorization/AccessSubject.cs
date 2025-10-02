using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authorization
{
    /// <summary>
    /// Represents accessing subject.
    /// </summary>
    public class AccessSubject
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessSubject"/> class.
        /// </summary>
        /// <param name="principal">The <see cref="AccessControlPrincipal"/>.</param>
        public AccessSubject(AccessControlPrincipal principal)
        {
            if (!principal.Identity.IsValid)
                throw new ArgumentException("The identity of principal is not valid.", nameof(principal));

            if (!principal.Identity.IsAuthenticated)
                throw new ArgumentException("The identity of principal is not authenticated.", nameof(principal));

            if (string.IsNullOrWhiteSpace(principal.AuthenticationToken))
                throw new ArgumentException("The principal has invalid authentication token.", nameof(principal));

            Identity = principal.Identity;
            AuthenticationToken = principal.AuthenticationToken;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AccessSubject"/> class.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AccessSubject()
        { }

        /// <summary>
        /// Gets the identity of principal.
        /// </summary>
        [JsonInclude]
        public AccessControlIdentity Identity { get; internal set; } = new AccessControlIdentity();

        /// <summary>
        /// Gets the authentication token.
        /// </summary>
        [JsonInclude]
        public string AuthenticationToken { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets if or not this represents valid access subject.
        /// </summary>
        [JsonIgnore]
        public bool IsValid
        {
            get { return Identity.IsValid && !string.IsNullOrWhiteSpace(AuthenticationToken); }
        }
    }
}
