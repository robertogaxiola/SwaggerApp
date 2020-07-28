using System.Linq;
using System.Text;
using System.Web;
using Newtonsoft.Json;

namespace SwaggerApp
{
    public class AuthorizeAttribute : System.Web.Http.AuthorizeAttribute
    {
        protected override void HandleUnauthorizedRequest(System.Web.Http.Controllers.HttpActionContext actionContext)
        {
            if (!HttpContext.Current.User.Identity.IsAuthenticated)
            {
                base.HandleUnauthorizedRequest(actionContext);

                // {
                // "Message": "Authorization has been denied for this request."
                // }

                string tk = string.Empty;
                var re = actionContext.Request;
                var headers = re.Headers;
                string meth = re.Method.ToString();
                if (headers.Contains("Authorization"))
                    tk = headers.GetValues("Authorization").FirstOrDefault().ToString();
                if (tk.StartsWith("Bearer "))
                    tk = tk.Replace("Bearer ", "");
                string stUri = actionContext.Request.RequestUri.AbsolutePath;
                VarsSubsFunc.AddCardexTokens(stUri, meth, (int)System.Net.HttpStatusCode.Unauthorized, System.Net.HttpStatusCode.Unauthorized.ToString(), VarsSubsFunc.GetIpAddress().Trim(), tk);
                var resp = new { Message = "Authorization has been denied for this request." };
                string yourJson = JsonConvert.SerializeObject(resp);
                actionContext.Response = new System.Net.Http.HttpResponseMessage()
                {
                    StatusCode = System.Net.HttpStatusCode.Unauthorized,
                    Content = new System.Net.Http.StringContent(yourJson, Encoding.UTF8, "application/json")
                };
            }
            else
            {
                string tk = string.Empty;
                var re = actionContext.Request;
                var headers = re.Headers;
                string meth = re.Method.ToString();
                if (headers.Contains("Authorization"))
                    tk = headers.GetValues("Authorization").FirstOrDefault().ToString();
                if (tk.StartsWith("Bearer "))
                    tk = tk.Replace("Bearer ", "");
                string stUri = actionContext.Request.RequestUri.AbsolutePath;
                VarsSubsFunc.AddCardexTokens(stUri, meth, (int)System.Net.HttpStatusCode.Forbidden, System.Net.HttpStatusCode.Forbidden.ToString(), VarsSubsFunc.GetIpAddress().Trim(), tk);
                actionContext.Response = new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.Forbidden);
            }
        }

        public override void OnAuthorization(System.Web.Http.Controllers.HttpActionContext actionContext)
        {
            if (!base.IsAuthorized(actionContext))
            {
                HandleUnauthorizedRequest(actionContext);
            }
            else
            {
                string tk = string.Empty;
                var re = actionContext.Request;
                var headers = re.Headers;
                string meth = re.Method.ToString();
                if (headers.Contains("Authorization"))
                    tk = headers.GetValues("Authorization").FirstOrDefault().ToString();
                if (tk.StartsWith("Bearer "))
                    tk = tk.Replace("Bearer ", "");
                string stUri = actionContext.Request.RequestUri.AbsolutePath;
                VarsSubsFunc.AddCardexTokens(stUri, meth, (int)System.Net.HttpStatusCode.Accepted, System.Net.HttpStatusCode.Accepted.ToString(), VarsSubsFunc.GetIpAddress().Trim(), tk);
            }
        }

        // Protected Overrides Function IsAuthorized(actionContext As Http.Controllers.HttpActionContext) As Boolean

        // If IsAuthorized Then

        // Dim tk As String = String.Empty
        // Dim re = actionContext.Request
        // Dim headers = re.Headers

        // If headers.Contains("Authorization") Then tk = headers.GetValues("Authorization").FirstOrDefault.ToString

        // If tk.StartsWith("Bearer ") Then tk = tk.Replace("Bearer ", "")

        // AddValidation(Net.HttpStatusCode.Accepted, Net.HttpStatusCode.Accepted.ToString, GetIpAddress.Trim, tk)

        // End If

        // Return MyBase.IsAuthorized(actionContext)

        // End Function

    }
}