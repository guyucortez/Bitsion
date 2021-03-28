using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using WebApi.Entities;

namespace WebApi.Controllers
{
    [Controller]
    public abstract class BaseController : ControllerBase
    {
        //public object Account2 => (object)User;
        //Devolvemos la cuenta actual autenticada
        public Account Account => (Account)HttpContext.Items["Account"];
    }
}
