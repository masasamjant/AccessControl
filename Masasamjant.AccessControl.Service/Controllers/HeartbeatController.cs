using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Masasamjant.AccessControl.Service.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HeartbeatController : ControllerBase
    {
        [Route("api/heartbeat")]
        public IActionResult Get()
        { }
    }
}
