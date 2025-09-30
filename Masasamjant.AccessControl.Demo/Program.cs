using Masasamjant.AccessControl.Authentication;
using Masasamjant.AccessControl.Demo.Services;
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
            builder.Services.AddTransient<IUserService, UserService>();
            builder.Services.AddTransient<IAuthenticationSecretProvider, UserService>();
            builder.Services.AddTransient<AccessControlAuthority, DemoAuthority>();
            builder.Services.AddTransient<Authenticator, DemoAuthenticator>();

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
            app.UseAuthorization();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseRouting();

            app.UseAuthorization();

            app.MapStaticAssets();
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}")
                .WithStaticAssets();

            app.Run();
        }
    }
}
