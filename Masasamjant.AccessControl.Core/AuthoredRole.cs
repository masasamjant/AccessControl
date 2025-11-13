using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents authored role.
    /// </summary>
    public class AuthoredRole : IAuthored
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AuthoredRole"/> with specified authority and name.
        /// </summary>
        /// <param name="authority">The authority.</param>
        /// <param name="name">The role name.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="name"/> is empty or only whitespace.</exception>
        /// <exception cref="ArgumentException">If value of <paramref name="name"/> contains <see cref="AccessControlValues.ItemSeparator"/>.</exception>
        public AuthoredRole(Authority authority, string name)
        {
            Name = ValidateName(name);
            Authority = authority;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AuthoredRole"/> class.
        /// </summary>
        public AuthoredRole()
        { }

        /// <summary>
        /// Gets the authority.
        /// </summary>
        [JsonInclude]
        public Authority Authority { get; internal set; } = new Authority();

        /// <summary>
        /// Gets the role name.
        /// </summary>
        [JsonInclude]
        public string Name { get; internal set; } = string.Empty;

        /// <summary>
        /// Check if specified name is valid role name.
        /// </summary>
        /// <param name="name">The role name.</param>
        /// <returns><c>true</c> if <paramref name="name"/> is valid role name; <c>false</c> otherwise.</returns>
        public static bool IsValidRoleName(string name)
        {
            return !string.IsNullOrWhiteSpace(name) && name.All(c => c != AccessControlValues.ItemSeparator);
        }

        internal static string ValidateName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The name of role is empty or only whitespace.");

            for (int index = 0; index < name.Length; index++)
            {
                char c = name[index];

                if (c == AccessControlValues.ItemSeparator)
                    throw new ArgumentException($"{c} character is not allowed in role name.", nameof(name));
            }

            return name;
        }

    }
}
