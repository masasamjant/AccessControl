using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authorization
{
    /// <summary>
    /// Represent request of access.
    /// </summary>
    public sealed class AccessRequest
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessRequest"/> class.
        /// </summary>
        /// <param name="subject">The access subject.</param>
        /// <param name="obj">The access object.</param>
        /// <param name="accessType">The access type.</param>
        /// <exception cref="ArgumentException">
        /// If <paramref name="subject"/> or <paramref name="obj"/> is not valid.
        /// -or-
        /// If value of <paramref name="accessType"/> is not defined.
        /// </exception>
        public AccessRequest(AccessSubject subject, AccessObject obj, AccessType accessType)
        {
            if (!subject.IsValid)
                throw new ArgumentException("The access subject is not valid.", nameof(subject));

            if (!obj.IsValid)
                throw new ArgumentException("The access object is not valid.", nameof(obj));

            if (!Enum.IsDefined(accessType))
                throw new ArgumentException("The value is not defined.", nameof(accessType));

            Subject = subject;
            Object = obj;
            AccessType = accessType;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AccessRequest"/> class.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AccessRequest()
        { }

        /// <summary>
        /// Gets the access subject.
        /// </summary>
        [JsonInclude]
        public AccessSubject Subject { get; internal set; } = new AccessSubject();

        /// <summary>
        /// Gets the access object.
        /// </summary>
        [JsonInclude]
        public AccessObject Object { get; internal set; } = new AccessObject();

        /// <summary>
        /// Gets the access type.
        /// </summary>
        [JsonInclude]
        public AccessType AccessType { get; internal set; }

        /// <summary>
        /// Gets if or not represents valid request.
        /// </summary>
        [JsonIgnore]
        public bool IsValid
        {
            get { return Subject.IsValid && Object.IsValid && Enum.IsDefined(AccessType); }
        }
    }
}
