using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authorization.Policies
{
    /// <summary>
    /// Represents access policy.
    /// </summary>
    public class AccessPolicy : IEquatable<AccessPolicy>
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessPolicy"/> class.
        /// </summary>
        /// <param name="name">The policy name.</param>
        /// <param name="accessObject">The access object.</param>
        /// <param name="enabled"><c>true</c> if policy is enabled; <c>false</c> otherwise.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="name"/> is empty or only whitespace.</exception>
        /// <exception cref="ArgumentException">
        /// If value of <paramref name="name"/> contains character that is not whitespace, ASCII digit or unicode letter.
        /// -or-
        /// If <paramref name="accessObject"/> is not valid access object.
        /// </exception>
        public AccessPolicy(string name, AccessObject accessObject, bool enabled)
        {
            if (!accessObject.IsValid)
                throw new ArgumentException("The access object is not valid.", nameof(accessObject));

            Name = ValidatePolicyName(name);
            Object = accessObject;
            IsEnabled = enabled;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AccessPolicy"/> class.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AccessPolicy()
        { }

        /// <summary>
        /// Gets the policy name.
        /// </summary>
        [JsonInclude]
        public string Name { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets the access object that is target of policy.
        /// </summary>
        [JsonInclude]
        public AccessObject Object { get; internal set; } = new AccessObject();

        /// <summary>
        /// Gets if or not access policy is enabled.
        /// </summary>
        [JsonInclude]
        public bool IsEnabled { get; internal set; }

        /// <summary>
        /// Gets if or not policy is valid.
        /// </summary>
        [JsonIgnore]
        public bool IsValid
        {
            get { return Object.IsValid && !string.IsNullOrWhiteSpace(Name); }
        }

        /// <summary>
        /// Check if other <see cref="AccessPolicy"/> is equal to this.
        /// </summary>
        /// <param name="other">The other <see cref="AccessPolicy"/>.</param>
        /// <returns><c>true</c> if <paramref name="other"/> has equal name and object; <c>false</c> otherwise.</returns>
        public bool Equals(AccessPolicy? other)
        {
            return other != null &&
                Object.Equals(other.Object) &&
                string.Equals(Name, other.Name, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Check if object instance is <see cref="AccessPolicy"/> and equal to this.
        /// </summary>
        /// <param name="obj">The object instance.</param>
        /// <returns><c>true</c> if <paramref name="obj"/> is <see cref="AccessPolicy"/> and equal to this; <c>false</c> otherwise.</returns>
        public override bool Equals(object? obj)
        {
            return Equals(obj as AccessPolicy);
        }

        /// <summary>
        /// Gets hash code.
        /// </summary>
        /// <returns>A hash code.</returns>
        public override int GetHashCode() 
        {
            return HashCode.Combine(Name, Object);
        }

        /// <summary>
        /// Gets string presentation.
        /// </summary>
        /// <returns>A string presentation.</returns>
        /// <remarks>This should only be used for debugging or logging purpose.</remarks>
        public override string ToString()
        {
            if (IsValid)
                return $"{Object}:{Name}";

            return string.Empty;
        }

        /// <summary>
        /// Validates the policy name.
        /// </summary>
        /// <param name="name">The policy name.</param>
        /// <returns>A <paramref name="name"/> if valid.</returns>
        /// <exception cref="ArgumentNullException">If value of <paramref name="name"/> is empty or only whitespace.</exception>
        /// <exception cref="ArgumentException">If value of <paramref name="name"/> contains character that is not whitespace, ASCII digit or unicode letter.</exception>
        public static string ValidatePolicyName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The policy name is empty or only whitespace.");

            foreach (char c in name)
            {
                if (char.IsWhiteSpace(c) || char.IsAsciiDigit(c) || char.IsLetter(c))
                    continue;
                else
                    throw new ArgumentException($"The policy name contains invalid character of '{c}'.", nameof(name));
            }

            return name;
        }
    }
}
