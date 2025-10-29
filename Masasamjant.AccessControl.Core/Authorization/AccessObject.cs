using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authorization
{
    /// <summary>
    /// Represents accessed object.
    /// </summary>
    public sealed class AccessObject : IEquatable<AccessObject>
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessObject"/> class. 
        /// The names can be validated using <see cref="ValidateApplicationName(string)"/> and <see cref="ValidateObjectName(string)"/> methods.
        /// </summary>
        /// <param name="application">The application name.</param>
        /// <param name="name">The object name.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="application"/> or <paramref name="name"/> is empty or contains only whitespace.</exception>
        /// <exception cref="ArgumentException">
        /// If value of <paramref name="name"/> do not start with unicode letter.
        /// -or-
        /// If value of <paramref name="application"/> or <paramref name="name"/> contains invalid characters.
        /// </exception>
        /// <remarks>Both names are trimmed so that they do not start or end with whitespace.</remarks>
        public AccessObject(string application, string name)
        {
            Application = ValidateApplicationName(application.Trim());
            Name = ValidateObjectName(name);
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AccessObject"/> class.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AccessObject()
        { }

        /// <summary>
        /// Gets the name of application.
        /// </summary>
        [JsonInclude]
        public string Application { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets the name of object.
        /// </summary>
        [JsonInclude]
        public string Name { get; internal set; } = string.Empty;

        /// <summary>
        /// Gets if or not represents valid object.
        /// </summary>
        [JsonIgnore]
        public bool IsValid
        {
            get { return !string.IsNullOrWhiteSpace(Application) && !string.IsNullOrWhiteSpace(Name); }
        }

        /// <summary>
        /// Check if other <see cref="AccessObject"/> is equal to this.
        /// </summary>
        /// <param name="other">The other <see cref="AccessObject"/>.</param>
        /// <returns><c>true</c> if <paramref name="other"/> is equal to this; <c>false</c> otherwise.</returns>
        public bool Equals(AccessObject? other)
        {
            if (other != null)
            {
                if (IsValid)
                {
                    return string.Equals(Application, other.Application, StringComparison.Ordinal) &&
                        string.Equals(Name, other.Name, StringComparison.Ordinal);
                }

                return IsValid == other.IsValid;
            }

            return false;
        }

        /// <summary>
        /// Check if object is <see cref="AccessObject"/> and equal to this.
        /// </summary>
        /// <param name="obj">The object instance.</param>
        /// <returns><c>true</c> if <paramref name="obj"/> is <see cref="AccessObject"/> and equal to this; <c>false</c> otherwise.</returns>
        public override bool Equals(object? obj)
        {
            return Equals(obj as AccessObject);
        }

        /// <summary>
        /// Gets hash code.
        /// </summary>
        /// <returns>A hash code.</returns>
        public override int GetHashCode()
        {
            if (!IsValid)
                return 0;

            return HashCode.Combine(Application, Name);
        }

        /// <summary>
        /// Gets string presentation.
        /// </summary>
        /// <returns>A string presentation.</returns>
        /// <remarks>This should only be used for debugging or logging purpose.</remarks>
        public override string ToString()
        {
            if (IsValid)
                return $"{Application}.{Name}";

            return string.Empty;
        }

        /// <summary>
        /// Validate application name.
        /// </summary>
        /// <param name="application">The application name.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">If value of <paramref name="application"/> is empty or only whitespace.</exception>
        /// <exception cref="ArgumentException">If value of <paramref name="application"/> contains slash or backslash character.</exception>
        /// <remarks>Slash and backslash characters are not allowed in application name.</remarks>
        public static string ValidateApplicationName(string application)
        {
            if (string.IsNullOrWhiteSpace(application))
                throw new ArgumentNullException(nameof(application), "The application name is empty or only whitespace.");

            char[] blacklist = ['\\', '/'];

            foreach (char c in application)
            {
                if (Array.IndexOf(blacklist, c) >= 0)
                    throw new ArgumentException($"The application name contains invalid character of '{c}'.", nameof(application));
            }

            return application;
        }

        /// <summary>
        /// Validate object name. The object name can consist from ASCII digits, unicode letters and underline. Besides 
        /// that name must start with letter.
        /// </summary>
        /// <param name="name">The object name.</param>
        /// <returns>A <paramref name="name"/> if valid.</returns>
        /// <exception cref="ArgumentNullException">If value of <paramref name="name"/> is empty or only whitespace.</exception>
        /// <exception cref="ArgumentException">
        /// If value of <paramref name="name"/> do not start with unicode letter.
        /// -or-
        /// If value of <paramref name="name"/> contains character that is not ASCII digit, unicode letter or underline.
        /// </exception>
        /// <remarks>Only special character allowed in object name is underline.</remarks>
        public static string ValidateObjectName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The object name is empty or only whitespace.");

            if (!char.IsDigit(name[0]))
                throw new ArgumentException(nameof(name), "The object name must start with letter.");

            char[] whitelist = ['_'];

            foreach (char c in name)
            {
                if (char.IsAsciiDigit(c) || char.IsLetter(c) || Array.IndexOf(whitelist, c) >= 0)
                    continue;
                else
                    throw new ArgumentException($"The object name contains invalid character of '{c}'.", nameof(name));
            }
            
            return name;
        }
    }
}
