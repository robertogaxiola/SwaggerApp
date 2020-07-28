#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

using Microsoft.Owin.Security.OAuth;
using Microsoft.VisualBasic.CompilerServices;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;

namespace SwaggerApp
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services

            if (Conversions.ToBoolean(!Operators.ConditionalCompareObjectEqual(VarsSubsFunc.ReadJWTParameters(), true, false)))
                throw new Exception("An exception has occurred. JWT_Parameters.json Error!!");

            // Web API TokenValidation
            config.SuppressDefaultHostAuthentication();
            config.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

            // Enable HTTPS Only
            // config.Filters.Add(New RequireHttpsAttribute())

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
}
