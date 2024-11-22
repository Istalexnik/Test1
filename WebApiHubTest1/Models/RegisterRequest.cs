using System.ComponentModel.DataAnnotations;

namespace WebApiHubTest1.Models;

public class RegisterRequest
{
    [Required]
    [EmailAddress(ErrorMessage = "Invalid email address.")]
    public string Email { get; init; } = string.Empty;

    [Required]
    [MinLength(5)]
    public string Password { get; init; } = string.Empty;
}
