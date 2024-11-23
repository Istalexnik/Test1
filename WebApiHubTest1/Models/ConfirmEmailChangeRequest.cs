using System.ComponentModel.DataAnnotations;

namespace WebApiHubTest1.Models
{
    public class ConfirmEmailChangeRequest
    {
        [Required]
        public string Code { get; set; } = string.Empty;
    }
}
