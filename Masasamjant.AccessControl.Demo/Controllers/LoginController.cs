using Masasamjant.AccessControl.Authentication;
using Masasamjant.AccessControl.Demo.Models;
using Masasamjant.Security.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Masasamjant.AccessControl.Demo.Controllers
{
    public class LoginController : Controller
    {
        private readonly Authenticator authenticator;
        private readonly IHashProvider hashProvider;
        private const string AuthenticationScheme = "PASSWORD";

        public LoginController(Authenticator authenticator, IHashProvider hashProvider)
        {
            this.authenticator = authenticator;
            this.hashProvider = hashProvider;
        }

        public IActionResult Index()
        {
            return View(new LoginViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> IndexAsync([FromForm] LoginViewModel model)
        {
            var request = new AuthenticationRequest(model.UserName, AuthenticationScheme);
            var requestResponse = authenticator.RequestAuthentication(request);

            if (!requestResponse.IsValid)
                return RedirectToAction(nameof(Index));


            var secretProvider = new ClientSecretProvider(model.UserName, model.Password, hashProvider);
            var secret = secretProvider.GetAuthenticationSecret(model.UserName, AuthenticationScheme);
            var challenge = requestResponse.CreateAuthenticationChallenge(secret, hashProvider);
            var response = authenticator.AuthenticateChallenge(challenge);
            
            if (response.Result == AuthenticationResult.Authenticated && response.Token != null)
            {
                var claims = new List<System.Security.Claims.Claim>();

                foreach (var claim in response.Token.Claims)
                {
                    var sysClaim = new System.Security.Claims.Claim(claim.Key, claim.Value);
                    claims.Add(sysClaim);
                }

                var claimsIdentity = new ClaimsIdentity(
                    claims, CookieAuthenticationDefaults.AuthenticationScheme);

                var authProperties = new AuthenticationProperties
                {
                    //AllowRefresh = <bool>,
                    // Refreshing the authentication session should be allowed.

                    //ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                    // The time at which the authentication ticket expires. A 
                    // value set here overrides the ExpireTimeSpan option of 
                    // CookieAuthenticationOptions set with AddCookie.

                    //IsPersistent = true,
                    // Whether the authentication session is persisted across 
                    // multiple requests. When used with cookies, controls
                    // whether the cookie's lifetime is absolute (matching the
                    // lifetime of the authentication ticket) or session-based.

                    //IssuedUtc = <DateTimeOffset>,
                    // The time at which the authentication ticket was issued.

                    //RedirectUri = <string>
                    // The full path or absolute URI to be used as an http 
                    // redirect response value.
                };

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                return RedirectToAction(nameof(Index), "Home");
            }

            return RedirectToAction(nameof(Index));
        }
    }
}
