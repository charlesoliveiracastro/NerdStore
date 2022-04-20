using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace NSE.Identidade.API.Models
{
    public class UserRegistration
    {
        [Required(ErrorMessage = "O campo {0} é obrigatório!")]
        [EmailAddress(ErrorMessage = "O campo {0} esta com formato inválido!")]
        public string Email { get; set; }
        [Required(ErrorMessage = "O campo {0} é obrigatório!")]
        [StringLength(100, ErrorMessage = "O campo {0} deve ter entre {2} e {1} caracteres!", MinimumLength = 6)]
        public string Password { get; set; }
        [Compare("Password", ErrorMessage = "As senhas nao conferem!")]
        public string PasswordConfirm { get; set; }
    }

    public class UserLogin
    {
        [Required(ErrorMessage = "O campo {0} é obrigatório!")]
        [EmailAddress(ErrorMessage = "O campo {0} esta com formato inválido!")]
        public string Email { get; set; }
        [Required(ErrorMessage = "O campo {0} é obrigatório!")]
        [StringLength(100, ErrorMessage = "O campo {0} deve ter entre {2} e {1} caracteres!", MinimumLength = 6)]
        public string Password { get; set; }
    }

    public class UserResponseLogin
    {

        public string AccessToken { get; set; }
        public double ExpiresIn { get; set; }
        public UserToken UserToken { get; set; }

    }

    public class UserToken
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public IEnumerable<UserClaim> Clains {get; set;}
    }

    public class UserClaim
    {
        public string Value { get; set; }
        public string Type { get; set; }
    }

}
