using Masasamjant.AccessControl.Authorization;
using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents access control role.
    /// </summary>
    public class AccessControlRole : IEquatable<AccessControlRole>
    {
        /// <summary>
        /// Separator of <see cref="ApplicationName"/> and <see cref="RoleName"/> in <see cref="FullName"/>.
        /// </summary>
        public const char NameSeparator = ':';

        /// <summary>
        /// Initializes new instance of the <see cref="AccessControlRole"/> class.
        /// </summary>
        /// <param name="roleName">The role name.</param>
        /// <param name="applicationName">The application name.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="roleName"/> or <paramref name="applicationName"/> is empty or only whitespace.</exception>
        /// <exception cref="ArgumentException">If value of <paramref name="roleName"/> or <paramref name="applicationName"/> contains <see cref="NameSeparator"/> character.</exception>
        public AccessControlRole(string roleName, string applicationName)
        {
            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentNullException(nameof(roleName), "The role name is empty or only whitespace.");

            if (string.IsNullOrWhiteSpace(applicationName))
                throw new ArgumentNullException(nameof(applicationName), "The application name is empty or only whitespace.");

            if (roleName.Contains(NameSeparator))
                throw new ArgumentException($"The role name cannot have {NameSeparator} character.", nameof(roleName));

            if (applicationName.Contains(NameSeparator))
                throw new ArgumentException($"The application name cannot have {NameSeparator} character.", nameof(applicationName));

            RoleName = roleName;
            ApplicationName = AccessObject.ValidateApplicationName(applicationName);
            FullName = ApplicationName + NameSeparator + RoleName;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AccessControlRole"/> class.
        /// </summary>
        public AccessControlRole()
        { }

        /// <summary>
        /// Gets the role name.
        /// </summary>
        [JsonInclude]
        public string RoleName { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets the application name.
        /// </summary>
        [JsonInclude]
        public string ApplicationName { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets the full name.
        /// </summary>
        /// <value><see cref="ApplicationName"/> and <see cref="RoleName"/> concated with <see cref="NameSeparator"/>.</value>
        [JsonInclude]
        public string FullName { get; internal set; } = string.Empty;

        [JsonIgnore]
        public bool IsEmpty
        {
            get { return string.IsNullOrWhiteSpace(FullName); }
        }

        public bool Equals(AccessControlRole? other)
        {
            if (other != null)
            {
                if (IsEmpty)
                    return other.IsEmpty;

                return string.Equals(FullName, other.FullName, StringComparison.Ordinal);
            }

            return false;
        }

        public override bool Equals(object? obj)
        {
            return Equals(obj as AccessControlRole);
        }

        public override int GetHashCode()
        {
            return FullName.GetHashCode();
        }

        public override string ToString()
        {
            return FullName;
        }
    }
}
