#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Description;
using Microsoft.VisualBasic.CompilerServices;
using Swagger.Net;
using Swagger.Net.Application;
using SwaggerApp;

[assembly: PreApplicationStartMethod(typeof(SwaggerConfig), "Register")]

namespace SwaggerApp
{
    /// <summary>
    /// ' '
    /// </summary>
    public class SwaggerConfig
    {
        /// <summary>
        /// Registro Swagger
        /// </summary>
        public static void Register()
        {
            //Crea Base de datos
            if (!VarsSubsFunc.Create_db())
                throw new Exception("An exception has occurred. REST_API.db Error!!");
            //lee parametros
            if (Conversions.ToBoolean(!VarsSubsFunc.ReadJWTParameters()))
                throw new Exception("An exception has occurred. JWT_Parameters.json Error!!");

            var thisAssembly = typeof(SwaggerConfig).Assembly;

            //carga validacion de swagger

            VarsSubsFunc.mBolSwagAuth = true;

            if (VarsSubsFunc.mBolSwagAuth)
                GlobalConfiguration.Configuration.MessageHandlers.Add(new SwaggerAccessMessageHandler2());

            GlobalConfiguration.Configuration
                .EnableSwagger(c =>
                    {
                        // By default, the service root url is inferred from the request used to access the docs.
                        // However, there may be situations (e.g. proxy and load-balanced environments) where this does not
                        // resolve correctly. You can workaround this by providing your own code to determine the root URL.
                        //
                        //c.RootUrl(req => GetRootUrlFromAppConfig());

                        // If schemes are not explicitly provided in a Swagger 2.0 document, then the scheme used to access
                        // the docs is taken as the default. If your API supports multiple schemes and you want to be explicit
                        // about them, you can use the "Schemes" option as shown below.
                        //
                        //c.Schemes(new[] { "http", "https" });

                        // Use "SingleApiVersion" to describe a single version API. Swagger 2.0 includes an "Info" object to
                        // hold additional metadata for an API. Version and title are required but you can also provide
                        // additional fields by chaining methods off SingleApiVersion.
                        //
                        //c.SingleApiVersion("v1", "SwaggerApp");

                        // Taking to long to load the swagger docs? Enable this option to start caching it
                        //
                        //c.AllowCachingSwaggerDoc();

                        // If you want the output Swagger docs to be indented properly, enable the "PrettyPrint" option.
                        //
                        //c.PrettyPrint();

                        // If your API has multiple versions, use "MultipleApiVersions" instead of "SingleApiVersion".
                        // In this case, you must provide a lambda that tells Swagger-Net which actions should be
                        // included in the docs for a given API version. Like "SingleApiVersion", each call to "Version"
                        // returns an "Info" builder so you can provide additional metadata per API version.
                        //
                        //c.MultipleApiVersions(
                        //    (apiDesc, targetApiVersion) => ResolveVersionSupportByRouteConstraint(apiDesc, targetApiVersion),
                        //    (vc) =>
                        //    {
                        //        vc.Version("v2", "Swagger-Net Dummy API V2");
                        //        vc.Version("v1", "Swagger-Net Dummy API V1");
                        //    });

                        // You can use "BasicAuth", "ApiKey" or "OAuth2" options to describe security schemes for the API.
                        // See https://github.com/swagger-api/swagger-spec/blob/master/versions/2.0.md for more details.
                        // NOTE: These only define the schemes and need to be coupled with a corresponding "security" property
                        // at the document or operation level to indicate which schemes are required for an operation. To do this,
                        // you'll need to implement a custom IDocumentFilter and/or IOperationFilter to set these properties
                        // according to your specific authorization implementation
                        //
                        //c.BasicAuth("basic").Description("Basic HTTP Authentication");
                        //
                        //c.ApiKey("apiKey", "header", "API Key Authentication");
                        //
                        //c.OAuth2("oauth2")
                        //    .Description("OAuth2 Implicit Grant")
                        //    .Flow("implicit")
                        //    .AuthorizationUrl("http://petstore.swagger.wordnik.com/api/oauth/dialog")
                        //    //.TokenUrl("https://tempuri.org/token")
                        //    .Scopes(scopes =>
                        //    {
                        //        scopes.Add("read", "Read access to protected resources");
                        //        scopes.Add("write", "Write access to protected resources");
                        //    });

                        // Set this flag to omit descriptions for any actions decorated with the Obsolete attribute
                        //c.IgnoreObsoleteActions();

                        // Comment this setting to disable Access-Control-Allow-Origin
                        //c.AccessControlAllowOrigin("*");

                        // Each operation be assigned one or more tags which are then used by consumers for various reasons.
                        // For example, the swagger-ui groups operations according to the first tag of each operation.
                        // By default, this will be controller name but you can use the "GroupActionsBy" option to
                        // override with any value.
                        //
                        //c.GroupActionsBy(apiDesc => apiDesc.HttpMethod.ToString());

                        // You can also specify a custom sort order for groups (as defined by "GroupActionsBy") to dictate
                        // the order in which operations are listed. For example, if the default grouping is in place
                        // (controller name) and you specify a descending alphabetic sort order, then actions from a
                        // ProductsController will be listed before those from a CustomersController. This is typically
                        // used to customize the order of groupings in the swagger-ui.
                        //
                        //c.OrderActionGroupsBy(new DescendingAlphabeticComparer());

                        // If you annotate Controllers and API Types with Xml comments:
                        // http://msdn.microsoft.com/en-us/library/b2s063f7(v=vs.110).aspx
                        // those comments will be incorporated into the generated docs and UI.
                        // Just make sure your comment file(s) have extension .XML
                        // You can add individual files by providing the path to one or
                        // more Xml comment files.
                        //
                        //c.IncludeXmlComments(AppDomain.CurrentDomain.BaseDirectory + "file.ext");
                        //c.IncludeAllXmlComments(thisAssembly, AppDomain.CurrentDomain.BaseDirectory);

                        // Swagger-Net makes a best attempt at generating Swagger compliant JSON schemas for the various types
                        // exposed in your API. However, there may be occasions when more control of the output is needed.
                        // This is supported through the "MapType" and "SchemaFilter" options:
                        //
                        // Use the "MapType" option to override the Schema generation for a specific type.
                        // It should be noted that the resulting Schema will be placed "inline" for any applicable Operations.
                        // While Swagger 2.0 supports inline definitions for "all" Schema types, the swagger-ui tool does not.
                        // It expects "complex" Schemas to be defined separately and referenced. For this reason, you should only
                        // use the "MapType" option when the resulting Schema is a primitive or array type. If you need to alter a
                        // complex Schema, use a Schema filter.
                        //
                        //c.MapType<ProductType>(() => new Schema { type = "integer", format = "int32" });

                        // If you want to post-modify "complex" Schemas once they've been generated, across the board or for a
                        // specific type, you can wire up one or more Schema filters.
                        //
                        //c.SchemaFilter<ApplySchemaVendorExtensions>();

                        // In a Swagger 2.0 document, complex types are typically declared globally and referenced by unique
                        // Schema Id. By default, Swagger-Net does NOT use the full type name in Schema Ids. In most cases, this
                        // works well because it prevents the "implementation detail" of type namespaces from leaking into your
                        // Swagger docs and UI. However, if you have multiple types in your API with the same class name, you'll
                        // need to opt out of this behavior to avoid Schema Id conflicts.
                        //
                        //c.UseFullTypeNameInSchemaIds();

                        // Alternatively, you can provide your own custom strategy for inferring SchemaId's for
                        // describing "complex" types in your API.
                        //
                        //c.SchemaId(t => t.FullName.Contains('`') ? t.FullName.Substring(0, t.FullName.IndexOf('`')) : t.FullName);

                        // Set this flag to omit schema property descriptions for any type properties decorated with the
                        // Obsolete attribute
                        //c.IgnoreObsoleteProperties();

                        // Set this flag to ignore IsSpecified members when serializing and deserializing types.
                        //
                        //c.IgnoreIsSpecifiedMembers();

                        // In accordance with the built in JsonSerializer, if disabled Swagger-Net will describe enums as integers.
                        // You can change the serializer behavior by configuring the StringToEnumConverter globally or for a given
                        // enum type. Swagger-Net will honor this change out-of-the-box. However, if you use a different
                        // approach to serialize enums as strings, you can also force Swagger-Net to describe them as strings.
                        //
                        //c.DescribeAllEnumsAsStrings(camelCase: false);

                        // Similar to Schema filters, Swagger-Net also supports Operation and Document filters:
                        //
                        // Post-modify Operation descriptions once they've been generated by wiring up one or more
                        // Operation filters.
                        //
                        //c.OperationFilter<AddDefaultResponse>();
                        //
                        // If you've defined an OAuth2 flow as described above, you could use a custom filter
                        // to inspect some attribute on each action and infer which (if any) OAuth2 scopes are required
                        // to execute the operation
                        //
                        //c.OperationFilter<AssignOAuth2SecurityRequirements>();

                        // Post-modify the entire Swagger document by wiring up one or more Document filters.
                        // This gives full control to modify the final SwaggerDocument. You should have a good understanding of
                        // the Swagger 2.0 spec. - https://github.com/swagger-api/swagger-spec/blob/master/versions/2.0.md
                        // before using this option.
                        //
                        //c.DocumentFilter<ApplyDocumentVendorExtensions>();

                        // In contrast to WebApi, Swagger 2.0 does not include the query string component when mapping a URL
                        // to an action. As a result, Swagger-Net will raise an exception if it encounters multiple actions
                        // with the same path (sans query string) and HTTP method. You can workaround this by providing a
                        // custom strategy to pick a winner or merge the descriptions for the purposes of the Swagger docs
                        //
                        //c.ResolveConflictingActions(apiDescriptions => apiDescriptions.First());

                        // Wrap the default SwaggerGenerator with additional behavior (e.g. caching) or provide an
                        // alternative implementation for ISwaggerProvider with the CustomProvider option.
                        //
                        //c.CustomProvider((defaultProvider) => new CachingSwaggerProvider(defaultProvider));

                        c.SingleApiVersion("v1", "SwaggerApp").Description("Simple pagina para pruebas de API").TermsOfService("Uso exclusivo desarrollo sistemas sierra.").Contact(cc => cc.Name("Roberto Gaxiola V.").Url("https://www.sierra.com.mx").Email("robertogaxiola@sierra.com.mx"));
                        c.IncludeXmlComments(string.Format(@"{0}\bin\" + thisAssembly.GetName().Name + ".XML", AppDomain.CurrentDomain.BaseDirectory));
                        c.OAuth2("oauth2").Flow("password").TokenUrl("/app/gettoken");
                        c.OperationFilter<AssignOAuth2SecurityRequirements>();
                        c.PrettyPrint();
                        c.OperationFilter<OptionalParameterOperationFilter>();
                        c.DocumentFilter<HideInDocsFilter>();
                    })
                .EnableSwaggerUi(c =>
                    {
                        // Use the "DocumentTitle" option to change the Document title.
                        // Very helpful when you have multiple Swagger pages open, to tell them apart.
                        //
                        //c.DocumentTitle("My Swagger UI");

                        // Use the "CssTheme" to add a theme to your UI.
                        // Options are:
                        //    theme-feeling-blue-css
                        //    theme-flattop-css
                        //    theme-material-css
                        //    theme-monokai-css
                        //    theme-muted-css
                        //    theme-newspaper-css
                        //    theme-outline-css
                        //
                        //c.CssTheme("");

                        // Use the "InjectStylesheet" option to enrich the UI with one or more additional CSS stylesheets.
                        // The file must be included in your project as an "Embedded Resource", and then the resource's
                        // "Logical Name" is passed to the method as shown below.
                        //
                        //c.InjectStylesheet(thisAssembly, "Swagger.Net.Dummy.SwaggerExtensions.testStyles1.css");

                        // Use the "InjectJavaScript" option to invoke one or more custom JavaScripts after the swagger-ui
                        // has loaded. The file must be included in your project as an "Embedded Resource", and then the resource's
                        // "Logical Name" is passed to the method as shown above.
                        //
                        //c.InjectJavaScript(thisAssembly, "Swagger.Net.Dummy.SwaggerExtensions.testScript1.js");

                        // The swagger-ui renders boolean data types as a dropdown. By default, it provides "true" and "false"
                        // strings as the possible choices. You can use this option to change these to something else,
                        // for example 0 and 1.
                        //
                        //c.BooleanValues(new[] { "0", "1" });

                        // Controls the display of vendor extension (x-) fields and values for Operations, Parameters, and Schema.
                        // The default is true.
                        //
                        //c.ShowExtensions(true);

                        // Show pattern, minLength, maxLength, minimum, and maximum fields
                        //
                        //c.ShowCommonExtensions(true);

                        // By default, swagger-ui will validate specs against swagger.io's online validator and display the result
                        // in a badge at the bottom of the page. Use these options to set a different validator URL or to disable the
                        // feature entirely.
                        //c.SetValidatorUrl("https://online.swagger.io/validator");
                        //c.DisableValidator();

                        // Use this option to control how the Operation listing is displayed.
                        // It can be set to "None" (default), "List" (shows operations for each resource),
                        // or "Full" (fully expanded: shows operations and their details).
                        //
                        //c.DocExpansion(DocExpansion.List);

                        // Controls how models are shown when the API is first rendered. (The user can always switch
                        // the rendering for a given model by clicking the 'Model' and 'Example Value' links.) It can be
                        // set to 'model' or 'example', and the default is 'example'.
                        //
                        //c.DefaultModelRendering(DefaultModelRender.Model);

                        // Use this option to control the expansion depth for the model on the model-example section.
                        //
                        //c.DefaultModelExpandDepth(0);

                        // The default expansion depth for models (set to -1 completely hide the models).
                        //
                        //c.DefaultModelsExpandDepth(0);

                        // Limit the number of operations shown to a smaller value
                        //
                        //c.UImaxDisplayedTags(100);

                        // Filter the operations works as a search, to disable set to "null"
                        //
                        //c.UIfilter("''");

                        // Specify which HTTP operations will have the 'Try it out!' option. An empty parameter list disables
                        // it for all operations.
                        //
                        //c.SupportedSubmitMethods("GET", "HEAD");

                        // Use the CustomAsset option to provide your own version of assets used in the swagger-ui.
                        // It's typically used to instruct Swagger-Net to return your version instead of the default
                        // when a request is made for "index.html". As with all custom content, the file must be included
                        // in your project as an "Embedded Resource", and then the resource's "Logical Name" is passed to
                        // the method as shown below.
                        //
                        //c.CustomAsset("index", thisAssembly, "YourWebApiProject.SwaggerExtensions.index.html");

                        // If your API has multiple versions and you've applied the MultipleApiVersions setting
                        // as described above, you can also enable a select box in the swagger-ui, that displays
                        // a discovery URL for each version. This provides a convenient way for users to browse documentation
                        // for different API versions.
                        //
                        //c.EnableDiscoveryUrlSelector();

                        // If your API supports the OAuth2 Implicit flow, and you've described it correctly, according to
                        // the Swagger 2.0 specification, you can enable UI support as shown below.
                        //
                        //c.EnableOAuth2Support(
                        //    clientId: "test-client-id",
                        //    clientSecret: null,
                        //    realm: "test-realm",
                        //    appName: "Swagger UI"
                        //    //additionalQueryStringParams: new Dictionary<string, string>() { { "foo", "bar" } }
                        //);

                        c.DocumentTitle("My Swagger UI");
                        c.EnableOAuth2Support("clientID", VarsSubsFunc.mStrSecretKey, "Swagger UI");
                    });






        }

        /// <summary>
        /// Filtro para authenticacion de token
        /// </summary>
        public class AssignOAuth2SecurityRequirements : IOperationFilter
        {
            public void Apply(Operation operation, SchemaRegistry schemaRegistry, ApiDescription apiDescription)
            {
                // Correspond each "Authorize" role to an oauth2 scope
                var scopes = apiDescription.ActionDescriptor.GetFilterPipeline().Select(filterInfo => filterInfo.Instance).OfType<AuthorizeAttribute>().SelectMany(attr => attr.Roles.Split(',')).Distinct();
                if (scopes.Any())
                {
                    if (operation.security is null)
                        operation.security = new List<IDictionary<string, IEnumerable<string>>>();
                    var oAuthRequirements = new Dictionary<string, IEnumerable<string>>() { { "oauth2", scopes } };
                    operation.security.Add(oAuthRequirements);
                }
            }
        }

        /// <summary>
        /// Filtro para agregar textbox para token
        /// </summary>
        public class AuthorizationHeaderParameterOperationFilter : IOperationFilter
        {
            public void Apply(Operation operation, SchemaRegistry schemaRegistry, ApiDescription apiDescription)
            {
                if (operation.parameters is null)
                    operation.parameters = new List<Swagger.Net.Parameter>();
                var param = new Swagger.Net.Parameter()
                {
                    name = "Authorization",
                    @in = "header",
                    description = "JWT Token",
                    required = false,
                    type = "string",
                    @default = "Bearer "
                };
                if (apiDescription.ActionDescriptor.GetCustomAttributes<AuthorizeAttribute>().Any() || apiDescription.ActionDescriptor.ControllerDescriptor.GetCustomAttributes<AuthorizeAttribute>().Any())
                {
                    param.required = true;
                    operation.parameters.Add(param);
                }
            }
        }

        /// <summary>
        /// Define parametros obligatorios u opcionales
        /// </summary>
        public class OptionalParameterOperationFilter : IOperationFilter
        {
            /// <summary>
            /// Sets appropriate Required status of parameters
            /// </summary>
            public void Apply(Operation operation, SchemaRegistry schemaRegistry, ApiDescription apiDescription)
            {
                if (operation.parameters is null)
                {
                    return;
                }

                var parameters = operation.parameters;
                foreach (var parameter in parameters)
                {
                    var param = operation.parameters.FirstOrDefault(x => string.Equals(x.name, parameter.name, StringComparison.InvariantCultureIgnoreCase));
                    if (param is null)
                    {
                        continue;
                    }

                    param.required = parameter.required;
                }
            }
        }

        /// <summary>
        /// Define atributos complejos
        /// </summary>
        public class ComplexTypeOperationFilter : IOperationFilter
        {
            public void Apply(Operation operation, SchemaRegistry schemaRegistry, ApiDescription apiDescription)
            {
                if (operation.parameters is null)
                    return;
                var parameters = apiDescription.ActionDescriptor.GetParameters();
                foreach (var parameter in parameters)
                {
                    foreach (var property in parameter.ParameterType.GetProperties())
                    {
                        var param = operation.parameters.FirstOrDefault(o => o.name.IndexOf(property.Name, StringComparison.InvariantCultureIgnoreCase) >= 0);
                        if (param is null)
                            continue;
                        string name = GetNameFromAttribute(property);
                        if (string.IsNullOrEmpty(name))
                        {
                            operation.parameters.Remove(param);
                        }

                        param.name = GetNameFromAttribute(property);
                    }
                }
            }

            private static string GetNameFromAttribute(PropertyInfo property)
            {
                var customAttributes = property.GetCustomAttributes(typeof(DataMemberAttribute), true);
                if (customAttributes.Length > 0)
                {
                    DataMemberAttribute attribute = customAttributes[0] as DataMemberAttribute;
                    if (attribute is object)
                        return attribute.Name;
                }

                return string.Empty;
            }
        }




        ///// <summary>
        ///// Metodos Originales
        ///// </summary>
        //public static bool ResolveVersionSupportByRouteConstraint(ApiDescription apiDesc, string targetApiVersion)
        //{
        //    return (apiDesc.Route.RouteTemplate.ToLower().Contains(targetApiVersion.ToLower()));
        //}

        //private class ApplyDocumentVendorExtensions : IDocumentFilter
        //{
        //    public void Apply(SwaggerDocument swaggerDoc, SchemaRegistry schemaRegistry, IApiExplorer apiExplorer)
        //    {
        //        // Include the given data type in the final SwaggerDocument
        //        //
        //        //schemaRegistry.GetOrRegister(typeof(ExtraType));
        //    }
        //}

        //public class AssignOAuth2SecurityRequirements : IOperationFilter
        //{
        //    public void Apply(Operation operation, SchemaRegistry schemaRegistry, ApiDescription apiDescription)
        //    {
        //        // Correspond each "Authorize" role to an oauth2 scope
        //        var scopes = apiDescription.ActionDescriptor.GetFilterPipeline()
        //            .Select(filterInfo => filterInfo.Instance)
        //            .OfType<AuthorizeAttribute>()
        //            .SelectMany(attr => attr.Roles.Split(','))
        //            .Distinct();

        //        if (scopes.Any())
        //        {
        //            if (operation.security == null)
        //                operation.security = new List<IDictionary<string, IEnumerable<string>>>();

        //            var oAuthRequirements = new Dictionary<string, IEnumerable<string>>
        //            {
        //                { "oauth2", scopes }
        //            };

        //            operation.security.Add(oAuthRequirements);
        //        }
        //    }
        //}

        //private class ApplySchemaVendorExtensions : ISchemaFilter
        //{
        //    public void Apply(Schema schema, SchemaRegistry schemaRegistry, Type type)
        //    {
        //        // Modify the example values in the final SwaggerDocument
        //        //
        //        if (schema.properties != null)
        //        {
        //            foreach (var p in schema.properties)
        //            {
        //                switch (p.Value.format)
        //                {
        //                    case "int32":
        //                        p.Value.example = 123;
        //                        break;
        //                    case "double":
        //                        p.Value.example = 9858.216;
        //                        break;
        //                }
        //            }
        //        }
        //    }
        //}
    }

    /// <summary>
    /// Autorizacion para acceso a API
    /// </summary>
    public class SwaggerAccessMessageHandler2 : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string userN = string.Empty;

            // If IsSwagger(request) AndAlso Not request.IsLocal() Then
            if (IsSwagger(request))
            {
                request.Headers.TryGetValues("Authorization", out IEnumerable<string> authHeaderValues);
                string authHeader = authHeaderValues?.FirstOrDefault();
                if (authHeader is object && authHeader.StartsWith("Basic "))
                {
                    string encodedUsernamePassword = authHeader.Split(' ')[1]?.Trim();
                    string decodedUsernamePassword = Encoding.UTF8.GetString(Convert.FromBase64String(encodedUsernamePassword));
                    string username = decodedUsernamePassword.Split(':')[0];
                    string password = decodedUsernamePassword.Split(':')[1];
                    userN = username;
                    if (IsAuthorized(username, password))
                    {
                        VarsSubsFunc.AddSwaggerCardex(request.RequestUri.PathAndQuery, (int)HttpStatusCode.Accepted, nameof(HttpStatusCode.Accepted), VarsSubsFunc.GetIpAddress().Trim(), userN);
                        return await base.SendAsync(request, cancellationToken);
                    }
                }

                VarsSubsFunc.AddSwaggerCardex(request.RequestUri.PathAndQuery, (int)HttpStatusCode.Unauthorized, nameof(HttpStatusCode.Unauthorized), VarsSubsFunc.GetIpAddress().Trim(), userN);
                var response = request.CreateResponse(HttpStatusCode.Unauthorized);
                response.Headers.Add("WWW-Authenticate", "Basic");
                return response;
            }
            else
            {
                // AddSwaggerCardex(request.RequestUri.PathAndQuery.ToString, Net.HttpStatusCode.Accepted, Net.HttpStatusCode.Accepted.ToString, GetIpAddress.Trim, userN)
                return await base.SendAsync(request, cancellationToken);
            }
        }

        public bool IsAuthorized(string username, string password)
        {
            string uName = string.Empty;
            string uPass = string.Empty;
            string uSt = string.Empty;
            int uID;
            if (!string.IsNullOrEmpty(username))
                username = username.ToLower();
            var lastaccess = DateTime.UtcNow;
            const string strSQLQuery = @"
SELECT id, username, password, status
FROM swagger
WHERE lower(username) = @username;
UPDATE swagger SET lastaccess = @lastaccess, lastipaddr = @ipaddr WHERE lower(username) = @username;";
            try
            {
                using (var connection = new System.Data.SQLite.SQLiteConnection(VarsSubsFunc.mStrSQLiteConnString))
                {
                    using (var command = new System.Data.SQLite.SQLiteCommand(strSQLQuery, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.Parameters.Add(new System.Data.SQLite.SQLiteParameter("@username", username));
                        command.Parameters.Add("@lastaccess", DbType.DateTime);
                        command.Parameters["@lastaccess"].Value = lastaccess;
                        command.Parameters.Add("@ipaddr", DbType.String);
                        command.Parameters["@ipaddr"].Value = VarsSubsFunc.GetIpAddress().Trim();
                        connection.Open();
                        using (var reader = command.ExecuteReader())
                        {
                            if (reader.HasRows)
                            {
                                while (reader.Read())
                                {
                                    uID = Conversions.ToInteger(reader[0]);
                                    uName = reader[1].ToString();
                                    uPass = reader[2].ToString();
                                    uSt = reader[3].ToString();
                                }
                            }
                        }
                    }
                }

                if (uName is null || string.IsNullOrEmpty(uName) || (uName ?? "") == (string.Empty ?? ""))
                {
                    return false;
                }

                if (uSt is null || uSt == "0" || (uSt ?? "") == (string.Empty ?? ""))
                {
                    return false;
                }

                if (!SimpleHash.VerifyHash(password, "SHA256", uPass))
                {
                    return false;
                }

                return true;
            }
            catch (Exception)
            {
                return false;
            }

            // Return username.Equals("admin", StringComparison.InvariantCultureIgnoreCase) AndAlso password.Equals("123456")
        }

        private bool IsSwagger(HttpRequestMessage request)
        {
            // Return request.RequestUri.PathAndQuery.StartsWith("/swagger")

            // Dim str As String
            // Dim str2 As String()

            // str = request.RequestUri.GetComponents(UriComponents.Path, UriFormat.Unescaped)

            // str2 = str.Split(New String() {"/swagger"}, StringSplitOptions.None)

            return request.RequestUri.PathAndQuery.IndexOf("/swagger", StringComparison.CurrentCultureIgnoreCase) >= 0;
        }
    }

    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
    public class HideInDocsAttribute : Attribute
    {
    }
        public class HideInDocsFilter : IDocumentFilter
    {
        public void Apply(SwaggerDocument swaggerDoc, SchemaRegistry schemaRegistry, IApiExplorer apiExplorer)
        {
            foreach (var apiDescription in apiExplorer.ApiDescriptions)
            {
                if (!apiDescription.ActionDescriptor.ControllerDescriptor.GetCustomAttributes<HideInDocsAttribute>().Any() && !apiDescription.ActionDescriptor.GetCustomAttributes<HideInDocsAttribute>().Any()) continue;
                var route = "/" + apiDescription.Route.RouteTemplate.TrimEnd('/');
                swaggerDoc.paths.Remove(route);
            }
        }
    }
}