Imports System
Imports System.Net
Imports System.Net.Http
Imports System.Text
Imports System.Web.Http
Imports Newtonsoft.Json
Imports Swagger.Net.Annotations

Namespace SwaggerApp.Controllers
    ''' <summary>
    ''' Metodos de Prueba
    ''' </summary>
    <SwaggerResponse(HttpStatusCode.Unauthorized, "Ha sido negada esta solicitud por falta de autorizacion.")>
    <SwaggerResponse(HttpStatusCode.Forbidden, "No tiene permisos para esta solicitud.")>
    <SwaggerResponse(HttpStatusCode.BadRequest, "Error en solicitud.")>
    <SwaggerResponse(HttpStatusCode.InternalServerError, "Error de aplicacion interno.")>
    <SwaggerApp.AuthorizeAttribute>
    Public Class TestController
        Inherits ApiController
        '''' <summary>
        '''' Consulta todos los datos
        '''' </summary>
        '''' <response code="200" cref="GetResponse">Operacion exitosa.</response>
        '[Route("testget")]
        '[ResponseType(typeof(GetResponse))]
        '[HttpGet]
        'public IHttpActionResult GetAll()
        '{
        '    HttpResponseMessage response;
        '    response = Request.CreateResponse(HttpStatusCode.OK);

        '    string jsonR = "{\"Nombre\":\"roberto\",\"Mensaje\":\"Respuesta Ok\"}";

        '    response.Content = new StringContent(jsonR, Encoding.UTF8, "application/json");
        '    response.Headers.Location = new Uri(Request.RequestUri.ToString());
        '    return base.ResponseMessage(response);
        '}

        '''' <summary>
        '''' Consulta un solo dato
        '''' </summary>
        '''' <response code="200" cref="GetResponse">Operacion exitosa.</response>
        '''' <param name="id">Numero de Documento</param>
        '[Route("testget/{id}")]
        '[ResponseType(typeof(GetResponse))]
        '[HttpGet]
        'public IHttpActionResult GetAll(string id)
        '{
        '    HttpResponseMessage response;
        '    response = Request.CreateResponse(HttpStatusCode.OK);

        '    string jsonR = "{\"Nombre\":\"roberto\",\"Mensaje\":\"Respuesta Ok\"}";

        '    response.Content = new StringContent(jsonR, Encoding.UTF8, "application/json");
        '    response.Headers.Location = new Uri(Request.RequestUri.ToString());
        '    return base.ResponseMessage(response);
        '}

        ''' <summary>
        ''' Consulta un solo dato mas parametros
        ''' </summary>
        ''' <responsecode="200"cref="GetResponse">Operacion exitosa.</response>
        ''' <paramname="id">Numero de documento</param>
        ''' <paramname="sort">1 = Ordenar por nombre (opcional)</param>
        <Route("get/{id}")>
        <Description.ResponseTypeAttribute(GetType(SwaggerApp.GetResponse))>
        <HttpGet>
        Public Function [Get](ByVal Optional id As Integer = 0, ByVal Optional sort As String = "0") As IHttpActionResult
            Dim response = Request.CreateResponse(HttpStatusCode.OK)

            'const string jsonR = "{\"id\":\" + id + "\",\"Mensaje\":\"Respuesta Ok\"}";

            Dim resp = New SwaggerApp.GetResponse() With {
                .Nombre = "Roberto",
                .Numero = id,
                .Mensaje = "Ya Existe."
            }
            Dim jsonR = JsonConvert.SerializeObject(resp)
            response.Content = New StringContent(jsonR, Encoding.UTF8, "application/json")
            response.Headers.Location = New Uri(Request.RequestUri.ToString() & "/" & id)
            Return MyBase.ResponseMessage(response)
        End Function

        ''' <summary>
        ''' Alta de Documento.
        ''' </summary>
        ''' <responsecode="201"cref="PostResponse">Alta de numero exitosa.</response>
        ''' <responsecode="303"cref="PostResponse">Numero ya se encontraba en el sistema (identificador en Location header, swagger redirecciona automaticamente.).</response>
        ''' <paramname="value">Datos del certificado.</param>
        <Route("post")>
        <Description.ResponseTypeAttribute(GetType(SwaggerApp.PostResponse))>
        <HttpPost>
        Public Function Post(
        <FromBody> ByVal value As SwaggerApp.PostData) As IHttpActionResult
            If value.Numero = 351 Then
                Dim resp = New SwaggerApp.PostResponse() With {
                    .Nombre = value.Nombre,
                    .Numero = value.Numero,
                    .Mensaje = "Ya Existe."
                }
                Dim jsonR = JsonConvert.SerializeObject(resp)
                Dim responseG = Request.CreateResponse(HttpStatusCode.SeeOther)
                responseG.Content = New StringContent(jsonR, Encoding.UTF8, "application/json")
                responseG.Headers.Location = New Uri(Request.RequestUri.ToString() & "/" & value.Numero)
                Return MyBase.ResponseMessage(responseG)
            Else
                Dim resp = New SwaggerApp.PostResponse() With {
                    .Nombre = value.Nombre,
                    .Numero = value.Numero,
                    .Mensaje = "Alta Correcta."
                }
                Dim jsonR = JsonConvert.SerializeObject(resp)
                Dim responseG = Request.CreateResponse(HttpStatusCode.Created)
                responseG.Content = New StringContent(jsonR, Encoding.UTF8, "application/json")
                responseG.Headers.Location = New Uri(Request.RequestUri.ToString() & "/" & value.Numero)
                Return MyBase.ResponseMessage(responseG)
            End If
        End Function

        ''' <summary>
        ''' Modificacion de Documento.
        ''' </summary>
        ''' <responsecode="200"cref="PostResponse">Modificacion de numero exitosa.</response>
        ''' <paramname="id">Numero a modificar</param>
        ''' <paramname="value">Datos del certificado.</param>
        <Route("put/{id}")>
        <Description.ResponseTypeAttribute(GetType(SwaggerApp.PostResponse))>
        <HttpPut>
        Public Function Put(ByVal id As Integer,
        <FromBody> ByVal value As SwaggerApp.PutData) As IHttpActionResult
            Dim resp = New SwaggerApp.PostResponse() With {
                .Nombre = value.Nombre,
                .Numero = id,
                .Mensaje = "Modificacion Correcta."
            }
            Dim jsonR = JsonConvert.SerializeObject(resp)
            Dim responseG = Request.CreateResponse(HttpStatusCode.Created)
            responseG.Content = New StringContent(jsonR, Encoding.UTF8, "application/json")
            responseG.Headers.Location = New Uri(Request.RequestUri.ToString() & "/" & id)
            Return MyBase.ResponseMessage(responseG)
        End Function

        ''' <summary>
        ''' Elimina Documento.
        ''' </summary>
        ''' <responsecode="200">Operacion exitosa.</response>
        ''' <paramname="id">Numero de documento</param>
        <Route("delete/{id}")>
        <HttpDelete>
        Public Function Delete(ByVal id As Integer) As IHttpActionResult
            Dim responseG = Request.CreateResponse(HttpStatusCode.OK)
            Return MyBase.ResponseMessage(responseG)
        End Function

        ''' <summary>
        ''' Actualizacion de Documento.
        ''' </summary>
        ''' <responsecode="200"cref="PostResponse">Modificacion de numero exitosa.</response>
        ''' <paramname="id">Numero a modificar</param>
        ''' <paramname="value">Datos del certificado.</param>
        <Route("patch/{id}")>
        <Description.ResponseTypeAttribute(GetType(SwaggerApp.PostResponse))>
        <HttpPatch>
        Public Function Patch(ByVal id As Integer,
        <FromBody> ByVal value As SwaggerApp.PutData) As IHttpActionResult
            Dim resp = New SwaggerApp.PostResponse() With {
                .Nombre = value.Nombre,
                .Numero = id,
                .Mensaje = "Modificacion Correcta."
            }
            Dim jsonR = JsonConvert.SerializeObject(resp)
            Dim responseG = Request.CreateResponse(HttpStatusCode.Created)
            responseG.Content = New StringContent(jsonR, Encoding.UTF8, "application/json")
            responseG.Headers.Location = New Uri(Request.RequestUri.ToString() & "/" & id)
            Return MyBase.ResponseMessage(responseG)
        End Function
    End Class
End Namespace
