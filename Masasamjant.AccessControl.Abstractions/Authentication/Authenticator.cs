using Microsoft.Extensions.Logging;

namespace Masasamjant.AccessControl.Authentication
{
    /// <summary>
    /// Represents abtract authenticator that is associated with <see cref="IAccessControlAuthority"/>.
    /// </summary>
    public abstract class Authenticator : IAuthenticator
    {
        /// <summary>
        /// Initializes new instance of the <see cref="Authenticator"/> class.
        /// </summary>
        /// <param name="authority">The <see cref="IAccessControlAuthority"/>.</param>
        protected Authenticator(IAccessControlAuthority authority)
        {
            Authority = authority;
            Logger = Authority.LoggerFactory.CreateLogger<Authenticator>();
        }

        /// <summary>
        /// Gets the <see cref="IAccessControlAuthority"/>.
        /// </summary>
        public IAccessControlAuthority Authority { get; }

        /// <summary>
        /// Gets the <see cref="ILogger{Authenticator}"/>.
        /// </summary>
        protected ILogger<Authenticator> Logger { get; }

        /// <summary>
        /// Write specified message to log if specified log level is enabled.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="level">The log level.</param>
        /// <param name="args">The arguments.</param>
        protected void WriteLogMessage(string message, LogLevel level)
        {
#pragma warning disable CA2254 // Template should be a static expression
            if (!Enum.IsDefined(level))
                return;

            if (Logger.IsEnabled(level))
                Logger.Log(level, message);
#pragma warning restore CA2254 // Template should be a static expression
        }
    }
}
