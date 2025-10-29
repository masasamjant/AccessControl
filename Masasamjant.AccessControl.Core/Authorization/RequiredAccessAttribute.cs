namespace Masasamjant.AccessControl.Authorization
{
    /// <summary>
    /// Attribute applied to class or method to define access required by object.
    /// </summary>

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = false)]
    public sealed class RequiredAccessAttribute : Attribute
    {
        /// <summary>
        /// Initializes new instance of the <see cref="RequiredAccessAttribute"/> class.
        /// </summary>
        /// <param name="applicationName">The application name.</param>
        /// <param name="objectName">The object name.</param>
        /// <param name="accessType">The access type.</param>
        /// <exception cref="ArgumentNullException">If value of <paramref name="applicationName"/> or <paramref name="objectName"/> is empty or only whitespace.</exception>
        public RequiredAccessAttribute(string applicationName, string objectName, AccessType accessType)
            : this(new AccessObject(applicationName, objectName), accessType)
        { }

        /// <summary>
        /// Initializes new instance of the <see cref="RequiredAccessAttribute"/> class.
        /// </summary>
        /// <param name="obj">The access object.</param>
        /// <param name="accessType">The access type.</param>
        /// <exception cref="ArgumentException">If <paramref name="obj"/> is not valid access object.</exception>
        public RequiredAccessAttribute(AccessObject obj, AccessType accessType)
        {
            if (!obj.IsValid)
                throw new ArgumentException("The access object is not valid.", nameof(obj));

            AccessObject = obj;
            AccessType = accessType;
        }

        /// <summary>
        /// Gets the access object.
        /// </summary>
        public AccessObject AccessObject { get; }

        /// <summary>
        /// Gets the access type.
        /// </summary>
        public AccessType AccessType { get; }
    }
}
