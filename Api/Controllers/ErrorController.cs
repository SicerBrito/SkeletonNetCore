using Api.Helpers.Errors;
using Microsoft.AspNetCore.Mvc;

namespace Api.Controllers;

    [Route("errors/{code}")]
    public class ErrorController : BaseApiController{
        public IActionResult Error(int code){
            return new ObjectResult(new ApiResponse(code));
        }
    }
