// RegistrationController.cs
namespace backend.Models
{
    internal class UserCredentials
    {
        public string EmpCode { get; set; }
        public string Password { get; set; }
        public string Salt { get; set; }
        public string Algo { get; set; }
    }
}