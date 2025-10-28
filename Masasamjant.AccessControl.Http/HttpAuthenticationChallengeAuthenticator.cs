using Masasamjant.AccessControl.Authentication;
using Masasamjant.Http;
using Masasamjant.Http.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Http
{
    public class HttpAuthenticationChallengeAuthenticator : HttpAuthenticator, IAuthenticationChallengeAuthenticator
    {
        public HttpAuthenticationChallengeAuthenticator(IHttpClientBuilder httpClientBuilder)
            : base(httpClientBuilder)
        { }

        public async Task<AuthenticationResultResponse> AuthenticateChallengeAsync(AuthenticationChallenge challenge)
        {
            var httpRequest = new HttpPostRequest<AuthenticationChallenge>("authentication/challengeAuthentication", challenge);
            var httpResponse = await HttpClient.PostAsync<AuthenticationResultResponse, AuthenticationChallenge>(httpRequest);
            if (httpResponse == null)
                return new AuthenticationResultResponse();
            return httpResponse;
        }

        public async Task<AuthenticationRequestResponse> RequestAuthenticationAsync(AuthenticationRequest request)
        {
            var httpRequest = new HttpPostRequest<AuthenticationRequest>("authentication/requestAuthentication", request);
            var httpResponse = await HttpClient.PostAsync<AuthenticationRequestResponse, AuthenticationRequest>(httpRequest);
            if (httpResponse == null)
                return new AuthenticationRequestResponse();
            return httpResponse;
        }
    }
}
