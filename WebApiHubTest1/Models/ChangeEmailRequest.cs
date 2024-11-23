using System.ComponentModel.DataAnnotations;

namespace WebApiHubTest1.Models
{
    public class ChangeEmailRequest
    {
        [Required]
        [EmailAddress]
        public string NewEmail { get; set; } = string.Empty;
    }
}
