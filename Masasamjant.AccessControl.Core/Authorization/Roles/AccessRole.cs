namespace Masasamjant.AccessControl.Authorization.Roles
{
    /// <summary>
    /// Represents <see cref="AccessControlRole"/> with information do role have access to object.
    /// </summary>
    public class AccessRole : AccessControlRole, IEquatable<AccessRole>
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessRole"/> class.
        /// </summary>
        /// <param name="roleName">The role name.</param>
        /// <param name="applicationName">The application name.</param>
        /// <param name="objectName"></param>
        /// <param name="result"></param>
        /// <exception cref="ArgumentException">If value of <paramref name="result"/> is not defined.</exception>
        /// <exception cref="ArgumentNullException">If value of <paramref name="roleName"/> is empty or only whitespace.</exception>
        public AccessRole(string roleName, AccessObject accessObject, AccessResult result)
            : base(roleName, accessObject.Application)
        {
            if (!accessObject.IsValid)
                throw new ArgumentException("The access object is not valid.", nameof(accessObject));

            if (!Enum.IsDefined(result))
                throw new ArgumentException("The value is not defined.", nameof(result));

            Object = accessObject;
            Result = result;
        }

        /// <summary>
        /// Gets the access object.
        /// </summary>
        public AccessObject Object { get; internal set; }

        /// <summary>
        /// Gets the access result is access denied or granted for role.
        /// </summary>
        public AccessResult Result { get; internal set; }

        /// <summary>
        /// Check if other <see cref="AccessRole"/> is equal to this.
        /// </summary>
        /// <param name="other">The other <see cref="AccessRole"/>.</param>
        /// <returns><c>true</c> if <paramref name="other"/> is equal with this; <c>false</c> otherwise.</returns>
        public bool Equals(AccessRole? other)
        {
            if (other != null && base.Equals(other))
            { 
                return Object.Equals(other.Object) && Result == other.Result;
            }

            return false;
        }

        /// <summary>
        /// Check if object instance is <see cref="AccessRole"/> and equal with this.
        /// </summary>
        /// <param name="obj">The object instance.</param>
        /// <returns><c>true</c> if <paramref name="obj"/> is <see cref="AccessRole"/> and equal with this; <c>false</c> otherwise.</returns>
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
            int code = base.GetHashCode();
            return HashCode.Combine(code, Object, Result);
        }
    }
}
