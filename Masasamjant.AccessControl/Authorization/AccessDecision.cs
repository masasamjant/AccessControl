using System.Text.Json.Serialization;

namespace Masasamjant.AccessControl.Authorization
{
    /// <summary>
    /// Represents access decision.
    /// </summary>
    public sealed class AccessDecision
    {
        /// <summary>
        /// Initializes new instance of the <see cref="AccessDecision"/> class.
        /// </summary>
        /// <param name="request">The access request.</param>
        /// <param name="result">The access result.</param>
        /// <exception cref="ArgumentException">
        /// If <paramref name="request"/> is not valid.
        /// -or-
        /// If value of <paramref name="result"/> is not defined.
        /// </exception>
        private AccessDecision(AccessRequest request, AccessResult result)
        {
            if (!request.IsValid)
                throw new ArgumentException("The access request is not valid.", nameof(request));

            if (!Enum.IsDefined(result))
                throw new ArgumentException("The value is not defined.", nameof(result));

            Request = request;
            Result = result;
        }

        /// <summary>
        /// Initializes new default instance of the <see cref="AccessDecision"/> class.
        /// </summary>
        /// <remarks>This is only for inheriting classes and serialization requirements.</remarks>
        public AccessDecision()
        { }

        /// <summary>
        /// Gets the access request.
        /// </summary>
        [JsonInclude]
        public AccessRequest Request { get; internal set; } = new AccessRequest();

        /// <summary>
        /// Gets the access result.
        /// </summary>
        [JsonInclude]
        public AccessResult Result { get; internal set; }

        /// <summary>
        /// Gets if or not represents valid decision.
        /// </summary>
        [JsonIgnore]
        public bool IsValid
        {
            get { return Request.IsValid && Enum.IsDefined(Result); }
        }

        internal static AccessDecision Denied(AccessRequest request)
            => new AccessDecision(request, AccessResult.Deny);

        internal static AccessDecision Granted(AccessRequest request)
            => new AccessDecision(request, AccessResult.Grant);
    }
}
