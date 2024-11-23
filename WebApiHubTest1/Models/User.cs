// Models/User.cs
namespace WebApiHubTest1.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public bool IsEmailConfirmed { get; set; }
        // Include other relevant fields as needed
    }
}
