using System;
using System.Data;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Web.Http;
using System.Web.Http.Description;
using Microsoft.VisualBasic;
using Newtonsoft.Json;
using Swagger.Net.Annotations;

namespace SwaggerApp.Controllers
{
    /// <summary>
    /// Metodos de Prueba
    /// </summary>
    [SwaggerResponse(HttpStatusCode.Unauthorized, "Ha sido negada esta solicitud por falta de autorizacion.")]
    [SwaggerResponse(HttpStatusCode.Forbidden, "No tiene permisos para esta solicitud.")]
    [SwaggerResponse(HttpStatusCode.BadRequest, "Error en solicitud.")]
    [SwaggerResponse(HttpStatusCode.InternalServerError, "Error de aplicacion interno.")]
    [Authorize]
    public class TestController : ApiController
    {
        ///// <summary>
        ///// Consulta todos los datos
        ///// </summary>
        ///// <response code="200" cref="GetResponse">Operacion exitosa.</response>
        //[Route("testget")]
        //[ResponseType(typeof(GetResponse))]
        //[HttpGet]
        //public IHttpActionResult GetAll()
        //{
        //    HttpResponseMessage response;
        //    response = Request.CreateResponse(HttpStatusCode.OK);

        //    string jsonR = "{\"Nombre\":\"roberto\",\"Mensaje\":\"Respuesta Ok\"}";

        //    response.Content = new StringContent(jsonR, Encoding.UTF8, "application/json");
        //    response.Headers.Location = new Uri(Request.RequestUri.ToString());
        //    return base.ResponseMessage(response);
        //}

        ///// <summary>
        ///// Consulta un solo dato
        ///// </summary>
        ///// <response code="200" cref="GetResponse">Operacion exitosa.</response>
        ///// <param name="id">Numero de Documento</param>
        //[Route("testget/{id}")]
        //[ResponseType(typeof(GetResponse))]
        //[HttpGet]
        //public IHttpActionResult GetAll(string id)
        //{
        //    HttpResponseMessage response;
        //    response = Request.CreateResponse(HttpStatusCode.OK);

        //    string jsonR = "{\"Nombre\":\"roberto\",\"Mensaje\":\"Respuesta Ok\"}";

        //    response.Content = new StringContent(jsonR, Encoding.UTF8, "application/json");
        //    response.Headers.Location = new Uri(Request.RequestUri.ToString());
        //    return base.ResponseMessage(response);
        //}

        /// <summary>
        /// Consulta un solo dato mas parametros
        /// </summary>
        /// <response code="200" cref="GetResponse">Operacion exitosa.</response>
        /// <param name="id">Numero de documento</param>
        /// <param name="sort">1 = Ordenar por nombre (opcional)</param>
        [Route("get/{id}")]
        [ResponseType(typeof(GetResponse))]
        [HttpGet]
        public IHttpActionResult Get(int id = 0, string sort = "0")
        {
            HttpResponseMessage response = Request.CreateResponse(HttpStatusCode.OK);

            //const string jsonR = "{\"id\":\" + id + "\",\"Mensaje\":\"Respuesta Ok\"}";

            var resp = new GetResponse()
            {
                Nombre = "Roberto",
                Numero = id,
                Mensaje = "Ya Existe."
            };

            string jsonR = JsonConvert.SerializeObject(resp);

            response.Content = new StringContent(jsonR, Encoding.UTF8, "application/json");
            response.Headers.Location = new Uri(Request.RequestUri.ToString() + "/" + id);
            return base.ResponseMessage(response);
        }

        /// <summary>
        /// Alta de Documento.
        /// </summary>
        /// <response code="201" cref="PostResponse">Alta de numero exitosa.</response>
        /// <response code="303" cref="PostResponse">Numero ya se encontraba en el sistema (identificador en Location header, swagger redirecciona automaticamente.).</response>
        /// <param name="value">Datos del certificado.</param>
        [Route("post")]
        [ResponseType(typeof(PostResponse))]
        [HttpPost]
        public IHttpActionResult Post([FromBody] PostData value)
        {
            if (value.Numero == 351)
            {
                var resp = new PostResponse()
                {
                    Nombre = value.Nombre,
                    Numero = value.Numero,
                    Mensaje = "Ya Existe."
                };

                string jsonR = JsonConvert.SerializeObject(resp);
                HttpResponseMessage responseG = Request.CreateResponse(HttpStatusCode.SeeOther);
                responseG.Content = new StringContent(jsonR, Encoding.UTF8, "application/json");
                responseG.Headers.Location = new Uri(Request.RequestUri.ToString() + "/" + value.Numero);
                return base.ResponseMessage(responseG);
            }
            else
            {
                var resp = new PostResponse()
                {
                    Nombre = value.Nombre,
                    Numero = value.Numero,
                    Mensaje = "Alta Correcta."
                };

                string jsonR = JsonConvert.SerializeObject(resp);

                HttpResponseMessage responseG = Request.CreateResponse(HttpStatusCode.Created);
                responseG.Content = new StringContent(jsonR, Encoding.UTF8, "application/json");
                responseG.Headers.Location = new Uri(Request.RequestUri.ToString() + "/" + value.Numero);
                return base.ResponseMessage(responseG);
            }
        }

        /// <summary>
        /// Modificacion de Documento.
        /// </summary>
        /// <response code="200" cref="PostResponse">Modificacion de numero exitosa.</response>
        /// <param name="id">Numero a modificar</param>
        /// <param name="value">Datos del certificado.</param>
        [Route("put/{id}")]
        [ResponseType(typeof(PostResponse))]
        [HttpPut]
        public IHttpActionResult Put(int id, [FromBody] PutData value)
        {
            var resp = new PostResponse()
            {
                Nombre = value.Nombre,
                Numero = id,
                Mensaje = "Modificacion Correcta."
            };

            string jsonR = JsonConvert.SerializeObject(resp);

            HttpResponseMessage responseG = Request.CreateResponse(HttpStatusCode.Created);
            responseG.Content = new StringContent(jsonR, Encoding.UTF8, "application/json");
            responseG.Headers.Location = new Uri(Request.RequestUri.ToString() + "/" + id);
            return base.ResponseMessage(responseG);
        }

        /// <summary>
        /// Elimina Documento.
        /// </summary>
        /// <response code="200">Operacion exitosa.</response>
        /// <param name="id">Numero de documento</param>
        [Route("delete/{id}")]
        [HttpDelete]
        public IHttpActionResult Delete(int id)
        {
            HttpResponseMessage responseG = Request.CreateResponse(HttpStatusCode.OK);
            return base.ResponseMessage(responseG);
        }

        /// <summary>
        /// Actualizacion de Documento.
        /// </summary>
        /// <response code="200" cref="PostResponse">Modificacion de numero exitosa.</response>
        /// <param name="id">Numero a modificar</param>
        /// <param name="value">Datos del certificado.</param>
        [Route("patch/{id}")]
        [ResponseType(typeof(PostResponse))]
        [HttpPatch]
        public IHttpActionResult Patch(int id, [FromBody] PutData value)
        {
            var resp = new PostResponse()
            {
                Nombre = value.Nombre,
                Numero = id,
                Mensaje = "Modificacion Correcta."
            };

            string jsonR = JsonConvert.SerializeObject(resp);

            HttpResponseMessage responseG = Request.CreateResponse(HttpStatusCode.Created);
            responseG.Content = new StringContent(jsonR, Encoding.UTF8, "application/json");
            responseG.Headers.Location = new Uri(Request.RequestUri.ToString() + "/" + id);
            return base.ResponseMessage(responseG);
        }
    }
}