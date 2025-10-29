using Masasamjant.AccessControl.Authentication;
using Masasamjant.AccessControl.Demo.Models;
using Masasamjant.AccessControl.Demo.Services;
using Masasamjant.Security.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

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
            var identitySecretProvider = new ClientSecretProvider(model.UserName, model.Password, hashProvider);
            var identity = new AccessControlIdentity(model.UserName, authority.Name);
            var process = new ChallengeAuthenticationProcess(authenticator, identitySecretProvider, hashProvider, DemoAuthority.AuthenticationScheme);
            var request = authority.CreateAuthenticationRequest(identity, DemoAuthority.AuthenticationScheme);
            var response = await process.AuthenticateAsync(identity);
            var principal = response.Principal;

            if (response.Result == AuthenticationResult.Authenticated && principal != null)
            {
                var claimsPrincipal = principal.CreateClaimsPrincipal();

                if (claimsPrincipal != null)
                {
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
                        claimsPrincipal,
                        authProperties);

                    return RedirectToAction(nameof(Index), "Home");
                }
            }

            return RedirectToAction(nameof(Index));
        }
    }
}
