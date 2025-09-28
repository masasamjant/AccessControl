using System.ComponentModel.DataAnnotations;

namespace Masasamjant.AccessControl.Demo.Models
{
    public class LoginViewModel
    {
        [DataType(DataType.Text)]
        public string UserName { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;
    }
}
