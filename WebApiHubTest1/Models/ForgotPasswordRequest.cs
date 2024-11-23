using System.ComponentModel.DataAnnotations;

namespace WebApiHubTest1.Models
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
    }
}
