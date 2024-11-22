namespace WebApiHubTest1.Models;

public class ConfirmEmailRequest
{
    public string Email { get; set; } = string.Empty;
    public string ConfirmationCode { get; set; } = string.Empty;
}

