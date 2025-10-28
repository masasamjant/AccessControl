using Masasamjant.AccessControl.Authentication;
using Masasamjant.Http;
using Masasamjant.Http.Abstractions;

namespace Masasamjant.AccessControl.Http
{
    public class HttpAuthenticationTokenAuthenticator : HttpAuthenticator, IAuthenticationTokenAuthenticator
    {
        public HttpAuthenticationTokenAuthenticator(IHttpClientBuilder httpClientBuilder)
            : base(httpClientBuilder) 
        { }

        public async Task<AuthenticationResultResponse> AuthenticateTokenAsync(string authenticationToken)
        {
            var httpRequest = new HttpPostRequest<string>("authentication/tokenAuthentication", authenticationToken);
            var httpResponse = await HttpClient.PostAsync<AuthenticationResultResponse, string>(httpRequest);
            if (httpResponse == null)
                return new AuthenticationResultResponse();
            return httpResponse;
        }
    }
}
