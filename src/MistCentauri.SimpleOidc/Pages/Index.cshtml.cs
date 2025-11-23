using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MistCentauri.SimpleOidc.Pages;

[Authorize]
public class IndexModel : PageModel
{
    public void OnGet()
    {
    }
}
