using Masasamjant.AccessControl.Authentication;
using Masasamjant.Security.Abstractions;
using System.Collections.Concurrent;

namespace Masasamjant.AccessControl.Demo.Services
{
    public class DemoAuthenticator : Authenticator
    {
        private static ConcurrentDictionary<Guid, AuthenticationRequest> requests = new ConcurrentDictionary<Guid, AuthenticationRequest>();

        public DemoAuthenticator(AccessControlAuthority authority, IHashProvider hashProvider) 
            : base(authority, hashProvider)
        { }

        protected override bool IsValidRequest(AuthenticationRequest request, out string? invalidReason)
        {
            invalidReason = null;
            return HasValidCreationTime(request.Created);
        }

        protected override bool IsValidChallenge(AuthenticationChallenge challenge, out string? invalidReason)
        {
            invalidReason = null;
            return HasValidCreationTime(challenge.Created);
        }

        protected override bool IsValidToken(AuthenticationToken token, out string? invalidReason)
        {
            invalidReason = null;
            return true;
        }

        private static bool HasValidCreationTime(DateTimeOffset value)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;

            if (value > now)
                return false;

            if (now.Subtract(value).TotalSeconds > TimeSpan.FromMinutes(5).TotalSeconds)
                return false;

            return true;
        }

        protected override void SaveAuthenticationRequest(AuthenticationRequest request)
        {
            requests.AddOrUpdate(request.Identifier, request, (k, v) => request);
        }

        protected override AuthenticationRequest? GetAuthenticationRequest(Guid identifier)
        {
            return requests.TryRemove(identifier, out var request) ? request : null;
        }
    }
}
