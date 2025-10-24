using Masasamjant.AccessControl.Authentication;
using Masasamjant.AccessControl.Authorization;
using Masasamjant.AccessControl.Demo.Services;
using Masasamjant.AccessControl.Web;
using Masasamjant.AccessControl.Web.Authentication;
using Masasamjant.AccessControl.Web.Authorization;
using Masasamjant.Security;
using Masasamjant.Security.Abstractions;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Masasamjant.AccessControl.Demo
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddControllersWithViews();

            var hashProvider = new SHA256HashProvider();
            builder.Services.AddSingleton<IHashProvider>(hashProvider);
            builder.Services.AddScoped<IUserService, UserService>();
            builder.Services.AddScoped<IAuthenticationSecretProvider, UserService>();
            builder.Services.AddSingleton<IAuthenticationItemValidator, DemoAuthenticationItemValidator>();
            builder.Services.AddSingleton<IAuthenticationRequestRepository, AuthenticationRequestRepository>();
            builder.Services.AddScoped<IAccessControlAuthority, DemoAuthority>();
            builder.Services.AddScoped<IAuthenticationChallengeAuthenticator, AuthenticationChallengeAuthenticator>();
            builder.Services.AddScoped<IAuthenticationTokenAuthenticator, AuthenticationTokenAuthenticator>();
            builder.Services.AddScoped<IAuthorizer, Authorizer>();
            builder.Services.AddAccessControlPrincipalStore("ACCESS-CONTROL-PRINCIPAL");
            builder.Services.AddAccessControlUrlProvider("/Home/Forbidden", "/Login", null);
            builder.Services.AddAuthenticationContextProvider();
            builder.Services.AddAuthorizationContextProvider();

            var service = new UserService(hashProvider);
            service.AddUser("admin", "Good4Life!");

            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
                    options.SlidingExpiration = true;
                    options.AccessDeniedPath = "/Home/Forbidden";
                    options.LoginPath = "/Login";
                    options.LogoutPath = "/Logout";
                });

            var app = builder.Build();
            app.UseAuthentication();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseRouting();

            app.UseAuthorization();
            app.UseAccessControl();

            app.MapStaticAssets();
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}")
                .WithStaticAssets();

            app.Run();
        }
    }
}
