using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSE.Identidade.API.Extensions;
using NSE.Identidade.API.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace NSE.Identidade.API.Controllers
{

    [Route("api/identity")]
    public class AuthController : MainController
    {

        private readonly SignInManager<IdentityUser> _signInManger;
        private readonly UserManager<IdentityUser> _userManger;
        private readonly AppSettings _appSettings;

        //IOptions<AppSettings> o IOptions faz com que a injeção de dependencia já traga todas as informaçoes do appsettings.json
        public AuthController(SignInManager<IdentityUser> signInManger, 
                                UserManager<IdentityUser> userManger, 
                                IOptions<AppSettings> appSettings)
        {
            _signInManger = signInManger;
            _userManger = userManger;
            _appSettings = appSettings.Value;
        }

        [HttpPost("new-account")]
        public async Task<ActionResult> Register(UserRegistration userReg)
        {
            if (!ModelState.IsValid) return CustomResponse(ModelState);

            var user = new IdentityUser()
            {
                UserName = userReg.Email,
                Email = userReg.Email,
                EmailConfirmed = true
            };

            var result = await _userManger.CreateAsync(user, userReg.Password);
            if (result.Succeeded)
            {
                return CustomResponse(await GenerateJwt(userReg.Email));
            }

            foreach (var error in result.Errors)
                AddProcessError(error.Description);

            return CustomResponse();
        }

        [HttpPost("Login")]
        public async Task<ActionResult> Login(UserLogin userLogin)
        {
            if (!ModelState.IsValid) return CustomResponse(ModelState);

            var result = await _signInManger.PasswordSignInAsync(userLogin.Email, userLogin.Password, false, true);

            if (result.Succeeded)
                return CustomResponse(await GenerateJwt(userLogin.Email));

            if (result.IsLockedOut)
            {
                AddProcessError("Usuário temporariamente bloqueado por tentativas inválidas");
                return CustomResponse();
            }

            AddProcessError("Usuário ou Senha incorretos");

            return BadRequest();
        }

        //Refatorar
        private async Task<UserResponseLogin> GenerateJwt(string email)
        {          
            var user = await _userManger.FindByEmailAsync(email);
            var clains = await _userManger.GetClaimsAsync(user);
            var userRoles = await _userManger.GetRolesAsync(user);

            clains.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            clains.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            clains.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            clains.Add(new Claim(JwtRegisteredClaimNames.Nbf, ToUnixEpochDate(DateTime.Now).ToString()));
            clains.Add(new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(DateTime.Now).ToString(), ClaimValueTypes.Integer64));

            foreach(var userRole in userRoles)
            {
                clains.Add(new Claim("role", userRole));
            }

            var identityClains = new ClaimsIdentity();
            identityClains.AddClaims(clains);

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);

            var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = _appSettings.Issuer,
                Audience = _appSettings.Audience,
                Subject = identityClains,
                Expires = DateTime.UtcNow.AddHours(_appSettings.ExpirationHours),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            });

            var encodingToken = tokenHandler.WriteToken(token);

            var response = new UserResponseLogin
            {
                AccessToken = encodingToken,
                ExpiresIn = TimeSpan.FromHours(_appSettings.ExpirationHours).TotalSeconds,
                UserToken = new UserToken
                {
                    Id = user.Id,
                    Email = user.Email,
                    Clains = clains.Select(c => new UserClaim { Type = c.Type, Value = c.Value })
                }
            };

            return response;
        }

        private static long ToUnixEpochDate(DateTime date) //Padrão de Data Uilizada para o JWT
            => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1978, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);


    }
}
