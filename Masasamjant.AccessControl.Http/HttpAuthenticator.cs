using Masasamjant.AccessControl.Authentication;
using Masasamjant.Http.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masasamjant.AccessControl.Http
{
    public abstract class HttpAuthenticator : IAuthenticator
    {
        private readonly IHttpClientBuilder httpClientBuilder;

        protected HttpAuthenticator(IHttpClientBuilder httpClientBuilder)
        {
            this.httpClientBuilder = httpClientBuilder;
        }

        protected IHttpClient HttpClient
        {
            get
            {
                var client = httpClientBuilder.Build("Authentication");
                return client;
            }
        }

        IAccessControlAuthority IAuthenticator.Authority => throw new NotSupportedException();
    }
}
