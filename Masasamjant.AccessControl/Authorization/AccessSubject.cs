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
        /// <param name="principal">The <see cref="IAccessControlPrincipal"/>.</param>
        public AccessSubject(IAccessControlPrincipal principal)
        {
            Identity = principal.GetAccessControlIdentity().Name;
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
        public string Identity { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets if or not this represents valid access subject.
        /// </summary>
        [JsonIgnore]
        public bool IsValid
        {
            get { return !string.IsNullOrWhiteSpace(Identity); }
        }
    }
}
