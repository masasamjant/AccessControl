using Masasamjant.AccessControl.Demo.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Masasamjant.AccessControl.Demo.Controllers
{
    [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    public class UserController : Controller
    {
        private readonly UserService service;

        public UserController(UserService service)
        {
            this.service = service;
        }

        public IActionResult Index()
        {
            return View();
        }
    }
}
