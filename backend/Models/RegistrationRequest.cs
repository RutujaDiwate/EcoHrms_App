// RegistrationController.cs
namespace backend.Models
{
    public class RegistrationRequest
    {
        public string EmpCode { get; internal set; }
        public string Password { get; internal set; }
        public object Name { get; internal set; }
        public object Email { get; internal set; }
    }
}