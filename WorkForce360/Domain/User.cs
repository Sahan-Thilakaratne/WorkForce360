using System.ComponentModel.DataAnnotations;

public class User
{
    public int Id { get; set; }

    [Required, MaxLength(100)]
    public string Username { get; set; }

    [Required]
    public string PasswordHash { get; set; }

    public string Email { get; set; }

    public string FullName { get; set; }

    public string Role { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}