#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

using System;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Jwt;
using Owin;

[assembly: OwinStartup(typeof(SwaggerApp.Startup))]

namespace SwaggerApp
{
    public class Startup

    {
        public void Configuration(IAppBuilder app)
        {
            // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=316888

            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            app.UseJwtBearerAuthentication(new JwtBearerAuthenticationOptions()
            {
                AuthenticationMode = AuthenticationMode.Active,
                TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = VarsSubsFunc.mStrIssuerURL, // some string, normally web url,
                    ValidAudience = VarsSubsFunc.mStrAudience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(VarsSubsFunc.mStrSecretKey)),
                    ValidateLifetime = true,
                    LifetimeValidator = LifetimeValidator
                }
            });
        }

        public bool LifetimeValidator(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (expires is object)
            {
                if (DateTime.UtcNow < expires == true)
                    return true;
            }

            return false;
        }
    }
}
