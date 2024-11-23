using System.ComponentModel.DataAnnotations;

namespace WebApiHubTest1.Models
{
    public class ResetPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string Code { get; set; } = string.Empty;

        [Required]
        [MinLength(5)]
        public string NewPassword { get; set; } = string.Empty;
    }
}
