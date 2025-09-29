using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authorization
{
    /// <summary>
    /// Represents accessed object.
    /// </summary>
    public class AccessObject
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessObject"/> class.
        /// </summary>
        /// <param name="application">The application name.</param>
        /// <param name="name">The object name.</param>
        /// <exception cref="ArgumentNullException">
        /// If value of <paramref name="application"/> is empty or only whitespace.
        /// -or-
        /// If value of <paramref name="name"/> is empty or only whitespace.
        /// </exception>
        public AccessObject(string application, string name)
        {
            if (string.IsNullOrWhiteSpace(application))
                throw new ArgumentNullException(nameof(application), "The application name is empty or only whitespace.");

            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The object name is empty or only whitespace.");

            Application = application;
            Name = name;
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
    }
}
