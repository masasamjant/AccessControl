using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents claim of <see cref="AccessControlPrincipal"/>.
    /// </summary>
    public sealed class AccessControlClaim
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessControlClaim"/> class.
        /// </summary>
        /// <param name="key">The claim key.</param>
        /// <param name="value">The claim value.</param>
        /// <param name="authority">The <see cref="IAccessControlAuthority"/> who author this claim.</param>
        /// <exception cref="ArgumentException">If value of <paramref name="key"/> is empty or only whitespace.</exception>
        public AccessControlClaim(string key, string value, string authority)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("The key is empty or only whitespace.", nameof(key));

            Key = key;
            Value = value;
            Authority = authority;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AccessControlClaim"/> class.
        /// </summary>
        public AccessControlClaim() 
        { }

        /// <summary>
        /// Gets the claim key.
        /// </summary>
        [JsonInclude]
        public string Key { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets the claim value.
        /// </summary>
        [JsonInclude]
        public string Value { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets the authority of this claim.
        /// </summary>
        [JsonInclude]
        public string Authority { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets if or not represents empty claim.
        /// </summary>
        [JsonIgnore]
        public bool IsEmpty
        {
            get { return string.IsNullOrWhiteSpace(Key); }
        }
    }
}
