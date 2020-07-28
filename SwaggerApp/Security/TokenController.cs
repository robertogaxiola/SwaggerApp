#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
using System;
using System.Collections.Generic;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Web.Http;
using System.Web.Http.Description;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using Microsoft.VisualBasic.CompilerServices;
using Newtonsoft.Json;

namespace SwaggerApp.SwaggerApp.Security
{
    // <RequireHttps>

    /// <summary>
    /// Tokens.
    /// </summary>
    [AllowAnonymous]
    public class TokenController : ApiController
    {
        private readonly object key = VarsSubsFunc.mStrSecretKey; // Secret key which will be used later during validation
        private readonly object issuer = VarsSubsFunc.mStrIssuerURL;  // normally this will be your site URL
        private readonly object audience = VarsSubsFunc.mStrAudience;
        private string strUser, strRole, strEmail, strValid, strPassHash;
        private int intUserId;
        private DateTime dtRefresh_token;
        private int intRefresh_token_Valid;
        private string strRefresh_token_Value;
        private string UserName;
        private string Password;
        private string Grant_type;
        private string Refresh_Token;
        private string strIp;

        /// <summary>
        /// Solicitud de token.
        /// </summary>
        [Route("gettoken")]
        [ResponseType(typeof(JSON_Token_Response))]
        [HttpPost]
        public IHttpActionResult Token(AuthRequest login)
        {
            string refresh_token_g;
            if (!VarsSubsFunc.Create_db())
                return base.ResponseMessage(ErrorResponse("internal_error", "sqlite error.", HttpStatusCode.ServiceUnavailable));
            if (Conversions.ToBoolean(!VarsSubsFunc.ReadJWTParameters()))
                return base.ResponseMessage(ErrorResponse("internal_error", "jwt_parameters.json error.", HttpStatusCode.InternalServerError));
            try
            {
                strIp = VarsSubsFunc.GetIpAddress().Trim();
                UserName = login.username;
                Password = login.password;
                Grant_type = login.grant_type;
                Refresh_Token = login.refresh_token;
                if ((Grant_type ?? "") == (string.Empty ?? ""))
                    return base.ResponseMessage(ErrorResponse("invalid_request", "Incorrect parameters.", HttpStatusCode.BadRequest));
                refresh_token_g = Guid.NewGuid().ToString().Replace("-", "");
            }
            catch (Exception)
            {
                return base.ResponseMessage(ErrorResponse("invalid_request", "Incorrect parameters.", HttpStatusCode.BadRequest));
            }

            if (Grant_type == "password")
            {
                if ((UserName ?? "") == (string.Empty ?? "") || (Password ?? "") == (string.Empty ?? ""))
                    return base.ResponseMessage(ErrorResponse("invalid_request", "Incorrect parameters.", HttpStatusCode.BadRequest));
                // If Password = String.Empty Then Return ResponseMessage(ErrorResponse("invalid_request", "Incorrect parameters.", HttpStatusCode.BadRequest))

                var UserD = VarsSubsFunc.QueryUserData(UserName);
                if (UserD.status == false)
                {
                    return base.ResponseMessage(ErrorResponse("sqlite_error", UserD.msg, HttpStatusCode.ServiceUnavailable));
                }
                else
                {
                    intUserId = UserD.userid;
                    strUser = UserD.user;
                    strPassHash = UserD.passHash;
                    strEmail = UserD.email;
                    strRole = UserD.role;
                    strValid = UserD.valid;
                }

                if (strUser is null || string.IsNullOrEmpty(strUser) || (strUser ?? "") == (string.Empty ?? ""))
                {
                    return base.ResponseMessage(ErrorResponse("invalid_grant", "The user name or password is incorrect.", HttpStatusCode.Unauthorized));
                }

                if (strValid is null || strValid == "0" || (strValid ?? "") == (string.Empty ?? ""))
                {
                    return base.ResponseMessage(ErrorResponse("invalid_grant", "Sorry your account is inactive. Please contact your administrator.", HttpStatusCode.Unauthorized));
                }

                if (SimpleHash.VerifyHash(Password, "SHA256", strPassHash) == false)
                {
                    return base.ResponseMessage(ErrorResponse("invalid_grant", "The user name or password is incorrect.", HttpStatusCode.Unauthorized));

                    // Return New With {.error = error_msg, msg}
                }

                if (!UpdateRefreshToken(intUserId, refresh_token_g))
                    return base.ResponseMessage(ErrorResponse("internal_error", "Error updating refresh_token.", HttpStatusCode.InternalServerError));
                string yourJsonG = CreateJWTToken(strUser, strRole, strEmail, refresh_token_g, intUserId);
                HttpResponseMessage responseG = Request.CreateResponse(HttpStatusCode.OK);
                responseG.Headers.Location = new Uri(Request.RequestUri.ToString() + "/");
                responseG.Content = new StringContent(yourJsonG, Encoding.UTF8, "application/json");
                return base.ResponseMessage(responseG);
            }

            // Return New With {
            // .access_token = jwt_token,
            // .token_type = "bearer",
            // .expires_in = CInt((l_Token.ValidTo - Date.UtcNow).TotalSeconds),
            // .userName = permClaims.Item(2).Value,
            // .issued = l_Token.ValidFrom.ToString("r"),
            // .expires = l_Token.ValidTo.ToString("r")
            // }

            else if (Grant_type == "refresh_token")
            {
                var refresh_tknD = QueryRefreshToken(Refresh_Token);
                if (refresh_tknD.Status == false)
                {
                    return base.ResponseMessage(ErrorResponse("sqlite_error", refresh_tknD.Msg, HttpStatusCode.ServiceUnavailable));
                }
                else
                {
                    intUserId = refresh_tknD.UserId;
                    intRefresh_token_Valid = refresh_tknD.IsValid;
                    strRefresh_token_Value = refresh_tknD.RefreshToken;
                    dtRefresh_token = refresh_tknD.Date;
                }

                if (strRefresh_token_Value is null || (strRefresh_token_Value ?? "") == (string.Empty ?? "") || string.IsNullOrEmpty(strRefresh_token_Value))
                {
                    return base.ResponseMessage(ErrorResponse("invalid_grant", "Invalid token (1023).", HttpStatusCode.Unauthorized));
                }

                var UserD = VarsSubsFunc.QueryUserData(intUserId.ToString(), 1);
                if (UserD.status == false)
                {
                    return base.ResponseMessage(ErrorResponse("sqlite_error", UserD.msg, HttpStatusCode.ServiceUnavailable));
                }
                else
                {
                    intUserId = UserD.userid;
                    strUser = UserD.user;
                    strPassHash = UserD.passHash;
                    strEmail = UserD.email;
                    strRole = UserD.role;
                    strValid = UserD.valid;
                }

                if (strUser is null || string.IsNullOrEmpty(strUser) || (strUser ?? "") == (string.Empty ?? ""))
                {
                    return base.ResponseMessage(ErrorResponse("invalid_grant", "Invalid token, user does not exists.", HttpStatusCode.Unauthorized));
                }

                if (strValid is null || strValid == "0" || (strValid ?? "") == (string.Empty ?? ""))
                {
                    return base.ResponseMessage(ErrorResponse("invalid_grant", "Invalid token, your account is inactive. Please contact your administrator.", HttpStatusCode.Unauthorized));
                }

                if (intRefresh_token_Valid == 0)
                {
                    return base.ResponseMessage(ErrorResponse("invalid_grant", "Invalid token (1030).", HttpStatusCode.Unauthorized));
                }

                if (!UpdateRefreshToken(intUserId, refresh_token_g))
                    return base.ResponseMessage(ErrorResponse("internal_error", "Error updating refresh_token.", HttpStatusCode.InternalServerError));
                string yourJsonG = CreateJWTToken(strUser, strRole, strEmail, refresh_token_g, intUserId);
                HttpResponseMessage responseG = Request.CreateResponse(HttpStatusCode.OK);
                responseG.Content = new StringContent(yourJsonG, Encoding.UTF8, "application/json");
                responseG.Headers.Location = new Uri(Request.RequestUri.ToString() + "/");
                return base.ResponseMessage(responseG);
            }
            else
            {
                return base.ResponseMessage(ErrorResponse("invalid_grant", "grant_type not recognized.", HttpStatusCode.BadRequest));
            }
        }

        /// <summary>
        /// Ver informacion del token.
        /// </summary>
        [Route("tokendata")]
        [ResponseType(typeof(Token_Extracted_Data))]
        [HttpPost]
        public IHttpActionResult TknData([FromBody] Validate_Token_Post token)
        {
            if (Conversions.ToBoolean(!VarsSubsFunc.ReadJWTParameters()))
                return base.ResponseMessage(ErrorResponse("internal_error", "jwt_parameters.json error.", HttpStatusCode.InternalServerError));
            if (Information.IsNothing(token))
                return base.ResponseMessage(ErrorResponse("request_error", "parameters error.", HttpStatusCode.BadRequest));
            HttpResponseMessage response;

            // Dim username, role, email, userid, jti, iss, aud As String
            // Dim iat_date, exp_date, nbf_date As String
            // Dim iat, exp, nbf As UInt64

            // 'Dim valueFromBody As String = JsonConvert.SerializeObject(value)

            // 'New Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            // 'New Claim("userid", intUserID),
            // 'New Claim("user", struser),
            // 'New Claim("role", strrole),
            // 'New Claim("email", stremail),
            // 'New Claim(JwtRegisteredClaimNames.Iat, unixDateTime, ClaimValueTypes.Integer64)

            // 'Dim tk1 As String = String.Empty
            // 'Dim re = Request
            // 'Dim headers = re.Headers

            // 'If headers.Contains("Authorization") Then
            // '    tk1 = headers.GetValues("Authorization").FirstOrDefault.ToString
            // 'End If

            // 'If tk1.StartsWith("Bearer ") Then
            // '    tk1 = tk1.Replace("Bearer ", "")
            // 'End If

            // Dim tk As Token_Extracted_Data_Structure = ExtractTokenData(token.token)

            // jti = tk.jti
            // userid = tk.userid
            // username = tk.username
            // role = tk.role
            // email = tk.email
            // nbf = tk.nbf
            // iat = tk.iat
            // exp = tk.exp
            // iss = tk.iss
            // aud = tk.aud
            // nbf_date = tk.nbf_date
            // iat_date = tk.iat_date
            // exp_date = tk.exp_date

            // 'Dim identity = TryCast(User.Identity, ClaimsIdentity)

            // 'For Each claim In identity.Claims

            // '    System.Console.WriteLine(claim.Type & ":" + claim.Value)

            // 'Next

            // 'If identity IsNot Nothing Then

            // '    Dim claims = identity.Claims
            // '    username = claims.Where(Function(p) Equals(p.Type, "user")).FirstOrDefault()?.Value
            // '    userid = claims.Where(Function(p) Equals(p.Type, "userid")).FirstOrDefault()?.Value
            // '    role = claims.Where(Function(p) Equals(p.Type, "role")).FirstOrDefault()?.Value
            // '    email = claims.Where(Function(p) Equals(p.Type, "emailaddress")).FirstOrDefault()?.Value

            // '    jti = claims.Where(Function(p) Equals(p.Type, JwtRegisteredClaimNames.Jti)).FirstOrDefault()?.Value
            // '    exp = claims.Where(Function(p) Equals(p.Type, JwtRegisteredClaimNames.Exp)).FirstOrDefault()?.Value
            // '    nbf = claims.Where(Function(p) Equals(p.Type, JwtRegisteredClaimNames.Nbf)).FirstOrDefault()?.Value
            // '    iat = claims.Where(Function(p) Equals(p.Type, JwtRegisteredClaimNames.Iat)).FirstOrDefault()?.Value

            // 'End If

            string stringJ = JsonConvert.SerializeObject(VarsSubsFunc.ExtractTokenData(token.token));
            response = Request.CreateResponse(HttpStatusCode.OK);
            response.Headers.Location = new Uri(Request.RequestUri.ToString() + "/");
            response.Content = new StringContent(stringJ, Encoding.UTF8, "application/json");
            return base.ResponseMessage(response);
        }

        /// <summary>
        /// Validar token
        /// </summary>
        [Route("validatetoken")]
        [ResponseType(typeof(Validate_Token_Response))]
        [HttpPost]
        public IHttpActionResult validateToken([FromBody] Validate_Token_Post token)
        {
            HttpResponseMessage response;
            var vtr = new Validate_Token_Response();
            if (Conversions.ToBoolean(!VarsSubsFunc.ReadJWTParameters()))
            {
                vtr.msg = "jwt_parameters.json error";
            }

            if (Information.IsNothing(token))
                vtr.msg = "request error";
            string tkn = token.token;
            var tk = VarsSubsFunc.ExtractTokenData(tkn);
            var dtN = DateTime.UtcNow;
            if (Information.IsNothing(tk.exp_date))
                vtr.msg = "Token Invalido";
            var dtExp = DateTime.ParseExact(tk.exp_date, "yyyy-MM-dd HH:mm:ss", null);
            if (dtExp > dtN)
            {
                vtr.msg = "Token Valido, Usuario = " + tk.username;
                vtr.isValid = Conversions.ToString(true);
            }
            else
            {
                vtr.msg = "Token Invalido";
                vtr.isValid = Conversions.ToString(false);
            }

            string stringR = JsonConvert.SerializeObject(vtr);
            response = Request.CreateResponse(HttpStatusCode.OK);
            response.Headers.Location = new Uri(Request.RequestUri.ToString() + "/");
            response.Content = new StringContent(stringR, Encoding.UTF8, "application/json");
            return base.ResponseMessage(response);
        }

        /// <summary>
        /// Validar refresh_token
        /// </summary>
        [Route("validaterefreshtoken")]
        [ResponseType(typeof(Validate_Refresh_Token_Response))]
        [HttpPost]
        public IHttpActionResult validateRefreshToken(Validate_Refresh_Token_Post refresh_token)
        {
            try
            {
                if (Conversions.ToBoolean(!VarsSubsFunc.ReadJWTParameters()))
                    return base.ResponseMessage(ErrorResponse("internal_error", "jwt_parameters.json error.", HttpStatusCode.InternalServerError));
                if (Information.IsNothing(refresh_token))
                    return base.ResponseMessage(ErrorResponse("request_error", "parameters error.", HttpStatusCode.BadRequest));
                string rfreshTkn = refresh_token.refresh_token;
                HttpResponseMessage response;
                if ((rfreshTkn ?? "") == (string.Empty ?? ""))
                    return base.ResponseMessage(ErrorResponse("invalid_request", "Incorrect parameters.", HttpStatusCode.BadRequest));
                var refresh_tknD = QueryRefreshToken(rfreshTkn);
                if (refresh_tknD.Status == false)
                {
                    return base.ResponseMessage(ErrorResponse("sqlite_error", refresh_tknD.Msg, HttpStatusCode.ServiceUnavailable));
                }
                else
                {
                    // Public Property Status() As Boolean
                    // Public Property Msg() As String
                    // Public Property RefreshToken() As String
                    // Public Property UserId() As Integer
                    // Public Property IsValid() As Integer
                    // Public Property [Date]() As DateTime

                    var reJSON = new Validate_Refresh_Token_Response()
                    {
                        userid = refresh_tknD.UserId.ToString(),
                        isValid = refresh_tknD.IsValid.ToString(),
                        date = refresh_tknD.Date.ToString("r")
                    };

                    // reJSON = New With {
                    // .userid = refresh_tknD.UserId.ToString,
                    // .isValid = refresh_tknD.IsValid.ToString,
                    // .date = refresh_tknD.Date.ToString("r")
                    // }

                    string stringR = JsonConvert.SerializeObject(reJSON);
                    response = Request.CreateResponse(HttpStatusCode.OK);
                    response.Headers.Location = new Uri(Request.RequestUri.ToString() + "/");
                    response.Content = new StringContent(stringR, Encoding.UTF8, "application/json");
                    return base.ResponseMessage(response);
                }
            }
            catch (Exception)
            {
                return base.ResponseMessage(ErrorResponse("invalid_request", "Incorrect parameters.", HttpStatusCode.BadRequest));
            }
        }

        private string CreateJWTToken(string struser, string strrole, string stremail, string refresh_token_g, int intUserID)
        {
            var securityKey = new SymmetricSecurityKey((byte[])Encoding.UTF8.GetBytes((string)key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var daTime = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day, DateTime.Now.Hour, DateTime.Now.Minute, DateTime.Now.Second, DateTimeKind.Local);
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            double unixDateTime = (daTime.ToUniversalTime() - epoch).TotalSeconds;

            // Create a List of Claims, Keep claims name short
            var permClaims = new List<Claim>() { new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString(), ClaimValueTypes.String), new Claim("userid", intUserID.ToString(), ClaimValueTypes.Integer), new Claim("user", struser, ClaimValueTypes.String), new Claim("role", strrole, ClaimValueTypes.String), new Claim("email", stremail, ClaimValueTypes.String), new Claim(JwtRegisteredClaimNames.Iat, unixDateTime.ToString(), ClaimValueTypes.Integer64) };

            // Create Security Token object by giving required parameters
            var l_Token = new JwtSecurityToken(Conversions.ToString(issuer), Conversions.ToString(audience), permClaims, notBefore: DateTime.UtcNow, expires: DateTime.UtcNow.AddMinutes(VarsSubsFunc.mIntMinutes), signingCredentials: credentials);
            string jwt_token = new JwtSecurityTokenHandler().WriteToken(l_Token);
            var handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtToken = handler.ReadToken(jwt_token) as JwtSecurityToken;
            string userFromToken = jwtToken.Claims.First(claim => claim.Type == "user").Value;
            string expiresFrom = jwtToken.Claims.First(claim => claim.Type == "nbf").Value;
            var respG = new JSON_Token_Response()
            {
                access_token = jwt_token,
                token_type = "bearer",
                refresh_token = refresh_token_g,
                expires_in = Conversions.ToInteger((l_Token.ValidTo - DateTime.UtcNow).TotalSeconds),
                userName = userFromToken,
                issued = l_Token.ValidFrom.ToString("r"),
                expires = l_Token.ValidTo.ToString("r")
            };
            return JsonConvert.SerializeObject(respG);
        }

        private bool UpdateRefreshToken(int intUserId, string strRefresh_token)
        {
            string BolR;
            try
            {

                // strSQLQuery = "REPLACE INTO tokens (userid, refresh_token, status) VALUES (@userid, @refresh_token, @status);"

                // strSQLQuery = "
                // INSERT INTO tokens
                // (userid, refresh_token, status)
                // SELECT
                // @userid as userid,
                // @refresh_token as refresh_token,
                // @status as status
                // FROM tokens
                // WHERE NOT EXISTS (SELECT * FROM tokens WHERE userid = @userid) LIMIT 1;

                // UPDATE tokens SET refresh_token = @refresh_token WHERE userid = @userid;"

                string strSQLQuery = @"
UPDATE tokens SET status = 0 WHERE userid = @userid;
INSERT INTO tokens (userid, refresh_token, status, ipaddr) VALUES (@userid, @refresh_token, @status, @ipaddr);"; // = "UPDATE tokens SET refresh_token = @refresh_token, status = @status WHERE userid = @userid"

                using (var connection = new System.Data.SQLite.SQLiteConnection(VarsSubsFunc.mStrSQLiteConnString))
                {
                    using (var command = new System.Data.SQLite.SQLiteCommand(strSQLQuery, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.Parameters.Add("@userid", DbType.Int32);
                        command.Parameters["@userid"].Value = intUserId;
                        command.Parameters.Add("@refresh_token", DbType.String);
                        command.Parameters["@refresh_token"].Value = strRefresh_token;
                        command.Parameters.Add("@status", DbType.Int32);
                        command.Parameters["@status"].Value = 1;
                        command.Parameters.Add("@ipaddr", DbType.String);
                        command.Parameters["@ipaddr"].Value = strIp;
                        connection.Open();
                        command.ExecuteNonQuery();
                        connection.Close();
                    }
                }

                BolR = Conversions.ToString(true);
            }
            catch (Exception)
            {
                BolR = Conversions.ToString(false);
            }

            return Conversions.ToBoolean(BolR);
        }

        private Refresh_Token_Data QueryRefreshToken(string strRefresh_token)
        {
            var tknData = new Refresh_Token_Data();
            try
            {
                string strSQLQuery = "SELECT * from tokens WHERE (refresh_token = @refresh_token);";
                using (var connection = new System.Data.SQLite.SQLiteConnection(VarsSubsFunc.mStrSQLiteConnString))
                {
                    using (var command = new System.Data.SQLite.SQLiteCommand(strSQLQuery, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.Parameters.Add("@refresh_token", DbType.String);
                        command.Parameters["@refresh_token"].Value = strRefresh_token;
                        connection.Open();
                        using (var reader = command.ExecuteReader())
                        {
                            if (reader.HasRows)
                            {
                                while (reader.Read())
                                {
                                    tknData.Date = Conversions.ToDate(reader[1]);
                                    tknData.UserId = Conversions.ToInteger(reader[2]);
                                    tknData.RefreshToken = Conversions.ToString(reader[3]);
                                    tknData.IsValid = Conversions.ToInteger(reader[4]);
                                    tknData.Ip = Conversions.ToString(reader[5]);
                                    tknData.Status = reader.HasRows;
                                    tknData.Msg = reader.FieldCount.ToString();
                                }
                            }
                        }

                        connection.Close();
                    }

                    tknData.Status = true;
                }
            }
            catch (Exception ex)
            {
                tknData.Status = false;
                tknData.Msg = ex.Message;
            }

            return tknData;
        }

        private HttpResponseMessage ErrorResponse(string error_msg, string msg, HttpStatusCode status)
        {
            HttpResponseMessage response;
            try
            {
                var resp = new JSON_Token_ResponseError()
                {
                    error = error_msg,
                    msg = msg
                };
                string yourJson = JsonConvert.SerializeObject(resp);
                response = Request.CreateResponse(status);
                response.Content = new StringContent(yourJson, Encoding.UTF8, "application/json");
            }
            catch (Exception ex)
            {
                var resp = new JSON_Token_ResponseError()
                {
                    error = "internal_error",
                    msg = ex.Message
                };
                string yourJson = JsonConvert.SerializeObject(resp);
                response = Request.CreateResponse(HttpStatusCode.InternalServerError);
                response.Headers.Location = new Uri(Request.RequestUri.ToString() + "/");
                response.Content = new StringContent(yourJson, Encoding.UTF8, "application/json");
            }

            return response;
        }
    }
}