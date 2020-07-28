using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;

namespace SwaggerApp
{

    /// <summary>
    /// Respuesta de GET
    /// </summary>
    public class GetResponse
    {
        /// <summary>
        /// nombre
        /// </summary>
        /// <example>
        /// Juan
        /// </example>
        public string Nombre { get; set; }
        /// <summary>
        /// Mensaje
        /// </summary>
        public string Mensaje { get; set; }
    }
    /// <summary>
    /// Respuesta de POST
    /// </summary>
    public class PostResponse
    {
        /// <summary>
        /// Numero
        /// </summary>
        /// <example>
        /// 351
        /// </example>
        public int Numero { get; set; }
        /// <summary>
        /// Nombre
        /// </summary>
        /// <example>
        /// Jose
        /// </example>
        public string Nombre { get; set; }
        /// <summary>
        /// Mensaje
        /// </summary>
        public string Mensaje { get; set; }
    }

    /// <summary>
    /// Datos para Alta
    /// </summary>
    public class PostData
    {
        /// <summary>
        /// Numero
        /// </summary>
        /// <example>
        /// 351
        /// </example>
        public int Numero { get; set; }
        /// <summary>
        /// Nombre
        /// </summary>
        /// <example>
        /// Juan
        /// </example>
        public string Nombre { get; set; }
    }

    /// <summary>
    /// Datos para Modificacion
    /// </summary>
    public class PutData
    {
        /// <summary>
        /// Nombre
        /// </summary>
        /// <example>
        /// Pedro
        /// </example>
        public string Nombre { get; set; }
    }


}