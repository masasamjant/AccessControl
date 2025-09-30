using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Authorization
{
    public class AccessControlListAuthorization : IAuthorization
    {
        private readonly ConcurrentDictionary<AccessObject, AccessControlList> accessControlLists;
        private readonly IAuthorizationResolver authorizationResolver;
        private readonly IAccessControlListFactory accessControlListFactory;

        public AccessControlListAuthorization(IAuthorizationResolver authorizationResolver, IAccessControlListFactory accessControlListFactory)
        {
            this.accessControlLists = new ConcurrentDictionary<AccessObject, AccessControlList>();
            this.accessControlListFactory = accessControlListFactory;
            this.authorizationResolver = authorizationResolver;
            this.authorizationResolver.InvalidateAuthorization += OnInvalidateAuthorization;
        }

        public AccessDecision Authorize(AccessRequest request)
        {
            var accessControlList = accessControlLists.GetOrAdd(request.Object, accessControlListFactory.CreateAccessControlList());

            var accessResult = accessControlList.GetAccessResult(request);

            if (accessResult.HasValue)
                return new AccessDecision(request, accessResult.Value);

            var accessDecision = authorizationResolver.Authorize(request);

            accessControlList.SetAccessResult(accessDecision);

            return accessDecision;
        }

        private void OnInvalidateAuthorization(object? sender, InvalidateAccessObjectEventArgs e)
        {
            var accessControlList = accessControlLists.GetOrAdd(e.Object, accessControlListFactory.CreateAccessControlList());
            accessControlList.Clear();
        }
    }
}
