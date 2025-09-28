using Masasamjant.Security.Abstractions;
using System.Text;

namespace Masasamjant.AccessControl.Demo.Models
{
    internal class UserPassword
    {
        public static UserPassword Create(string username, string password, IHashProvider hashProvider)
        {
            var value = username + password;
            var bytes = value.GetByteArray(Encoding.Unicode);
            var hash = Convert.ToBase64String(hashProvider.HashData(bytes));
            return new UserPassword()
            {
                PasswordHash = hash,
                PasswordData = Convert.FromBase64String(hash)
            };
        }

        public required string PasswordHash { get; init; }

        public required byte[] PasswordData { get; init; }
    }
}
