using System;
using System.Net;
using System.Net.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace SwaggerApp
{
    public class RequireHttpsAttribute : AuthorizationFilterAttribute
    {
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            if (!Equals(actionContext.Request.RequestUri.Scheme, Uri.UriSchemeHttps))
            {
                actionContext.Response = new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    ReasonPhrase = "HTTPS Required for this call",
                    Content = new StringContent("HTTPS Required for this call")
                };
            }
            else
            {
                base.OnAuthorization(actionContext);
            }
        }
    }
}