#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
using System;

namespace SwaggerApp.SwaggerApp.Security
{
    /// <summary>
    /// Solicitud de token
    /// </summary>
    public class AuthRequest
    {
        /// <summary>
        /// usuario
        /// </summary>
        public string username { get; set; } = "";

        /// <summary>
        /// contraseña
        /// </summary>
        public string password { get; set; } = "";

        /// <summary>
        /// token nuevo = "password" // refresh token = "refresh_token"
        /// </summary>
        public string grant_type { get; set; }

        /// <summary>
        /// refresh token
        /// </summary>
        public string refresh_token { get; set; } = "";
    }

    public class Refresh_Token_Data
    {
        public bool Status { get; set; }
        public string Msg { get; set; }
        public string RefreshToken { get; set; }
        public int UserId { get; set; }
        public int IsValid { get; set; }
        public DateTime Date { get; set; }
        public string Ip { get; set; }
    }

    public class Validate_Token_Post
    {
        public string token { get; set; }
    }

    public class Validate_Token_Response
    {
        public string msg { get; set; }
        public string isValid { get; set; }
    }

    public class Validate_Refresh_Token_Post
    {
        public string refresh_token { get; set; }
    }

    public class Validate_Refresh_Token_Response
    {
        public string userid { get; set; }
        public string isValid { get; set; }
        public string date { get; set; }
    }
}