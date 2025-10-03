using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization.Roles
{
    /// <summary>
    /// Represents <see cref="AccessControlRole"/> with information does role have access to object specified by name.
    /// </summary>
    public class AccessRole : AccessControlRole
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessRole"/> class.
        /// </summary>
        /// <param name="roleName">The role name.</param>
        /// <param name="applicationName">The application name.</param>
        /// <param name="objectName"></param>
        /// <param name="result"></param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public AccessRole(string roleName, string applicationName, string objectName, AccessResult result)
            : base(roleName, applicationName)
        {
            if (!Enum.IsDefined(result))
                throw new ArgumentException("The value is not defined.", nameof(result));

            if (string.IsNullOrWhiteSpace(objectName))
                throw new ArgumentNullException(nameof(objectName), "The object name is empty or only whitespace.");

            ObjectName = objectName;
            Result = result;
        }

        /// <summary>
        /// Gets the name of accessed object.
        /// </summary>
        public string ObjectName { get; internal set; }

        /// <summary>
        /// Gets the access result is access denied or granted for role.
        /// </summary>
        public AccessResult Result { get; internal set; }
    }
}
