using Masasamjant.AccessControl.Authentication;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents access control authority.
    /// </summary>
    public class Authority : IEquatable<Authority>
    {
        /// <summary>
        /// Initializes new instance of the <see cref="Authority"/> class.
        /// </summary>
        /// <param name="uri">The URI to identify authority.</param>
        /// <param name="name">The authority name.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="name"/> is empty or only whitespace.</exception>
        public Authority(Uri uri, string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The name is empty or only whitespace.");

            Uri = uri;
            Name = name.Trim();
        }

        /// <summary>
        /// Initializes new default instance of <see cref="Authority"/> class that represents local authority.
        /// </summary>
        public Authority()
        { }

        /// <summary>
        /// Gets the name.
        /// </summary>
        [JsonInclude]
        public string Name { get; internal set; } = AccessControlValues.LocalAuthorityName;

        /// <summary>
        /// Get the URI to identify authority.
        /// </summary>
        [JsonInclude]
        public Uri Uri { get; internal set; } = AccessControlValues.LocalAuthorityUri;

        /// <summary>
        /// Check if is authoring specified <see cref="IAuthored"/> item.
        /// </summary>
        /// <param name="authored">The <see cref="IAuthored"/> item.</param>
        /// <returns><c>true</c> if this is authority of <paramref name="authored"/>; <c>false</c> otherwise.</returns>
        public bool IsAuthoring(IAuthored authored)
            => Equals(authored.Authority);

        /// <summary>
        /// Creates new authentication request.
        /// </summary>
        /// <param name="identityName">The identity name.</param>
        /// <returns>A <see cref="AuthenticationRequest"/>.</returns>
        public AuthenticationRequest CreateAuthenticationRequest(string identityName, UserSecretType secretType)
        { 
            var identity = new AuthoredIdentity(this, identityName, null);
            return new AuthenticationRequest(identity, secretType);
        }

        /// <summary>
        /// Check if other authority is equal to this instance.
        /// </summary>
        /// <param name="other">The other authority.</param>
        /// <returns><c>true</c> if this and other authority has same URI and name; <c>false</c> otherwise.</returns>
        public bool Equals(Authority? other)
        {
            return other != null &&
                Uri.Equals(other.Uri) &&
                string.Equals(Name, other.Name, StringComparison.Ordinal);
        }

        /// <summary>
        /// Check if object instance is authority and equal to this instance.
        /// </summary>
        /// <param name="obj">The object instance.</param>
        /// <returns><c>true</c> if <paramref name="obj"/> is authority and equal to this; <c>false</c> otherwise.</returns>
        public override bool Equals(object? obj)
        {
            return Equals(obj as Authority);
        }

        /// <summary>
        /// Gets hash code.
        /// </summary>
        /// <returns>A hash code.</returns>
        public override int GetHashCode()
        {
            return HashCode.Combine(Uri, Name);
        }

        /// <summary>
        /// Gets the string representation of this authority.
        /// </summary>
        /// <returns>A <see cref="Name"/>.</returns>
        public override string ToString()
        {
            return Name;
        }
    }
}
