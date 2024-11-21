using System.ComponentModel.DataAnnotations;

namespace WebApiHubTest1.Models;

public class RegisterRequest
{
    [Required]
    [MinLength(3)]
    public string Username { get; init; } = string.Empty;

    [Required]
    [MinLength(5)]
    public string Password { get; init; } = string.Empty;
}
