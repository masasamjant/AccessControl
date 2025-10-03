using Masasamjant.AccessControl.Authentication;
using Masasamjant.AccessControl.Demo.Models;
using Masasamjant.AccessControl.Demo.Services;
using Masasamjant.Security.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Masasamjant.AccessControl.Demo.Controllers
{
    public class LoginController : Controller
    {
        private IAccessControlAuthority authority;
        private readonly IAuthenticationChallengeAuthenticator authenticator;
        private readonly IHashProvider hashProvider;
        
        public LoginController(IAccessControlAuthority authority, IAuthenticationChallengeAuthenticator authenticator, IHashProvider hashProvider)
        {
            this.authority = authority;
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
            var identity = new AccessControlIdentity(model.UserName);
            var request = authority.CreateAuthenticationRequest(identity, DemoAuthority.AuthenticationScheme);
            var requestResponse = await authenticator.RequestAuthenticationAsync(request);

            if (!requestResponse.IsValid)
                return RedirectToAction(nameof(Index));

            var secretProvider = new ClientSecretProvider(model.UserName, model.Password, hashProvider);
            var secret = await secretProvider.GetAuthenticationSecretAsync(identity, DemoAuthority.AuthenticationScheme);
            var challenge = requestResponse.Request.CreateAuthenticationChallenge(secret, hashProvider);
            var response = await authenticator.AuthenticateChallengeAsync(challenge);
            var principal = response.Principal;

            if (response.Result == AuthenticationResult.Authenticated && principal != null && !string.IsNullOrWhiteSpace(principal.AuthenticationToken))
            {
                var claims = new List<Claim>();

                foreach (var claim in principal.Claims)
                {
                    var sysClaim = new Claim(claim.Key, claim.Value, null, claim.Authority);
                    claims.Add(sysClaim);
                }

                claims.Add(new Claim("AuthenticationToken", principal.AuthenticationToken, null, authority.Name));
                claims.Add(new Claim("AuthenticationScheme", DemoAuthority.AuthenticationScheme, null, authority.Name));

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
