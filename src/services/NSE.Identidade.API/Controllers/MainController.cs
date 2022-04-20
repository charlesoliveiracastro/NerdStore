using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using System.Collections.Generic;
using System.Linq;

namespace NSE.Identidade.API.Controllers
{
    [ApiController]
    public abstract class MainController : Controller
    {
        protected ICollection<string> Erros = new List<string>();

        protected ActionResult CustomResponse(object result = null)
        {
            if (IsValidOperation())
                return Ok(result);

            return BadRequest(new ValidationProblemDetails(
                new Dictionary<string, string[]>
                {
                    { "Mensagens", Erros.ToArray() }
                }));
        }

        protected ActionResult CustomResponse(ModelStateDictionary modelState)
        {
            var erros = modelState.Values.SelectMany(e => e.Errors);
            foreach(var erro in erros)
            {
                AddProcessError(erro.ErrorMessage);
            }

            return CustomResponse();
        }

        protected bool IsValidOperation()
        {
            return !Erros.Any();
        }

        protected void AddProcessError(string erro)
        {
            Erros.Add(erro);
        }

        protected void ClearProcessError()
        {
            Erros.Clear();
        }
    }
}
