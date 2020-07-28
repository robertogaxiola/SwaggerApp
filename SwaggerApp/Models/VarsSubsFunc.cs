using System;
using System.Configuration;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;
using Microsoft.VisualBasic;
using Microsoft.VisualBasic.CompilerServices;
using Newtonsoft.Json;

namespace SwaggerApp
{
    /// <summary>
    /// Data
    /// </summary>
    public static class VarsSubsFunc
    {

        // Public mPathRoot As String = System.Web.Hosting.HostingEnvironment.MapPath("~/")

        public static string mPathRoot; // = HttpContext.Current.Server.MapPath("~/App_Data/")
        public static string mPathAppDataRoot; // = HttpContext.Current.Server.MapPath("~/App_Data/")
        public static JWT_Data JWT_Paratemers_Data = new JWT_Data();
        public static string mStrLogSuffix = "_Pdv";
        public static string mStrDocsPreFolder = @"SierraDocs\";
        public static string mPathAppDocs = Path.GetPathRoot(Environment.SystemDirectory) + mStrDocsPreFolder + "WebApi" + mStrLogSuffix + @"\";
        public static string mPathWEBAPI = Path.GetPathRoot(Environment.SystemDirectory) + mStrDocsPreFolder + @"WebApi\";
        public static string mStrJWTParametersFile = mPathWEBAPI + @"Cfg\JWT_Parameters.json";
        public static string mStrSQLiteDBFile = mPathWEBAPI + @"Data\REST_API.db";
        public static string mStrSQLServer = ConfigurationManager.AppSettings["JWT_SQL_SERVER"];
        public static string mStrDBPassword = ConfigurationManager.AppSettings["JWT_SQLITE_PASSWORD"];
        public static string mStrSecretKey = ConfigurationManager.AppSettings["JWT_SECRET_KEY"];
        public static string mStrIssuerURL = ConfigurationManager.AppSettings["JWT_ISSUER_TOKEN"];
        public static string mStrAudience = ConfigurationManager.AppSettings["JWT_AUDIENCE_TOKEN"];
        public static int mIntMinutes = Conversions.ToInteger(ConfigurationManager.AppSettings["JWT_EXPIRE_MINUTES"]);
        public static string mStrSQLiteConnString = "Data Source=" + mStrSQLiteDBFile + ";Version=3;New=False;Compress=True;";
        public static bool mBolSwagAuth;

        public static bool ReadJWTParameters()
        {
            try
            {
                Directory.CreateDirectory(mPathWEBAPI + "Cfg");
                if (File.Exists(mStrJWTParametersFile))
                {
                    string cfgJSON = File.ReadAllText(mStrJWTParametersFile);
                    JWT_Paratemers_Data = JsonConvert.DeserializeObject<JWT_Data>(cfgJSON);
                }
                else
                {
                    JWT_Paratemers_Data.JWT_AUDIENCE_TOKEN = "https://localhost";
                    JWT_Paratemers_Data.JWT_ISSUER_TOKEN = "https://localhost";
                    JWT_Paratemers_Data.JWT_SECRET_KEY = "LL4v3_53Cr374_jW7_513Rr4_zOzO";
                    JWT_Paratemers_Data.JWT_SQLITE_PASSWORD = "pUn70_d3_V3n74";
                    JWT_Paratemers_Data.JWT_SQL_SERVER = Dns.GetHostName().ToString() + @"\SQLExpress,1433";
                    JWT_Paratemers_Data.JWT_EXPIRE_MINUTES = 120;
                    string strT = JsonConvert.SerializeObject(JWT_Paratemers_Data, Formatting.Indented).ToString();
                    using (var sw = new StreamWriter(mStrJWTParametersFile, false))
                    {
                        sw.Write(strT);
                    }

                    // Throw New System.Exception("An exception has occurred.")

                }

                mStrSQLServer = JWT_Paratemers_Data.JWT_SQL_SERVER;
                mStrDBPassword = JWT_Paratemers_Data.JWT_SQLITE_PASSWORD;
                mStrSecretKey = JWT_Paratemers_Data.JWT_SECRET_KEY;
                mStrIssuerURL = JWT_Paratemers_Data.JWT_ISSUER_TOKEN;
                mStrAudience = JWT_Paratemers_Data.JWT_AUDIENCE_TOKEN;
                mIntMinutes = JWT_Paratemers_Data.JWT_EXPIRE_MINUTES;
                mStrSQLiteConnString = "Data Source=" + mStrSQLiteDBFile + ";Version=3;New=False;Compress=True;Password=" + mStrDBPassword + ";";
                mStrSQLiteConnString = "Data Source=" + mStrSQLiteDBFile + ";Version=3;New=False;Compress=True;"; // Password=" & mStrDBPassword & ";"
                try
                {
                    string strSQLQuery = "SELECT * FROM params";
                    using (var connection = new System.Data.SQLite.SQLiteConnection(mStrSQLiteConnString))
                    {
                        using (var command = new System.Data.SQLite.SQLiteCommand(strSQLQuery, connection))
                        {
                            command.CommandType = CommandType.Text;
                            connection.Open();
                            using (var reader = command.ExecuteReader())
                            {
                                if (reader.HasRows)
                                {
                                    while (reader.Read())
                                        mBolSwagAuth = Conversions.ToBoolean(reader[1]);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    mBolSwagAuth = false;
                }

                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public static string GetIpAddress()
        {
            try
            {
                string ipAddressString = HttpContext.Current.Request.UserHostAddress;
                if (ipAddressString is null)
                    return null;
                IPAddress ipAddress = null;
                IPAddress.TryParse(ipAddressString, out ipAddress);
                if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    ipAddress = Dns.GetHostEntry(ipAddress).AddressList.First(x => x.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                }

                return ipAddress.ToString().PadLeft(15);
            }
            catch (Exception ex)
            {
                return "xxx.xxx.xxx.xxx";
            }
        }

        public static void WriteActivityLog(string st, int intL = 0)
        {
            try
            {
                Directory.CreateDirectory(mPathAppDocs + "Logs");
                string dtn = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss:ffff");
                StreamWriter objWriter;
                switch (intL)
                {
                    case 0:
                        {
                            objWriter = new StreamWriter(mPathAppDocs + @"Logs\WebApi" + mStrLogSuffix + "_Activity.log", true);
                            break;
                        }

                    case 1:
                        {
                            objWriter = new StreamWriter(mPathAppDocs + @"Logs\WebApi" + mStrLogSuffix + ".log", true);
                            break;
                        }

                    case 2:
                        {
                            objWriter = new StreamWriter(mPathAppDocs + @"Logs\WebApi" + mStrLogSuffix + "_Error.log", true);
                            break;
                        }

                    default:
                        {
                            objWriter = new StreamWriter(mPathAppDocs + @"Logs\WebApi" + mStrLogSuffix + "_Activity.log", true);
                            break;
                        }
                }

                objWriter.WriteLine("<<- " + dtn + " ->>  " + st);
                objWriter.Close();
            }
            catch (Exception ex)
            {
                //
            }
        }

        public static bool Create_db()
        {
            bool bolR;
            var con = new System.Data.SQLite.SQLiteConnection();
            var cmd = new System.Data.SQLite.SQLiteCommand();
            string str_sql;
            bolR = true;
            Directory.CreateDirectory(mPathWEBAPI + "Data");
            if (!File.Exists(mStrSQLiteDBFile))
            {
                try
                {
                    System.Data.SQLite.SQLiteConnection.CreateFile(mStrSQLiteDBFile);
                    con = new System.Data.SQLite.SQLiteConnection() { ConnectionString = mStrSQLiteConnString };
                    con.Open();
                    // con.ChangePassword(mStrDBPassword)
                    cmd.Connection = con;
                    str_sql = Conversions.ToString(Operators.ConcatenateObject(Operators.ConcatenateObject(Operators.ConcatenateObject(Operators.ConcatenateObject(Operators.ConcatenateObject(Operators.ConcatenateObject(@"
                    CREATE TABLE IF NOT EXISTS [users] (
                    [id] INTEGER PRIMARY KEY ASC AUTOINCREMENT NOT NULL DEFAULT 1,
                    [username] VARCHAR(50) NOT NULL,
                    [name] VARCHAR(512) NOT NULL,
                    [password] VARCHAR(512) NOT NULL,
                    [email] VARCHAR(512) DEFAULT (null),
                    [role] VARCHAR(512) DEFAULT (null),
                    [status] INTEGER DEFAULT (1),
                    [lastaccess] DATETIME NOT NULL DEFAULT (DATETIME('now')),
                    [laststatus] INTEGER DEFAULT (200),
                    [lastipaddr] VARCHAR(20)
                    );
                    UPDATE [sqlite_sequence] SET seq = 1 WHERE name = 'users';
                    CREATE UNIQUE INDEX [id]
                    ON [users] (
                    [id] ASC
                    );

                    INSERT INTO users (username, name, password, role) VALUES ('admin', 'Administrator', '", PrepMySQLString(SimpleHash.ComputeHash("123456", "SHA256", null))), @"', 'Administrators');
                    INSERT INTO users (username, name, password, email, role) VALUES ('robs', 'Roberto Gaxiola', '"), PrepMySQLString(SimpleHash.ComputeHash("123456", "SHA256", null))), @"', 'recgaxiola@gmail.com', 'Administrators');

                    CREATE TABLE IF NOT EXISTS [tokens] (
                    [id] INTEGER NOT NULL DEFAULT 1 PRIMARY KEY AUTOINCREMENT,
                    [date] DATETIME NOT NULL DEFAULT (DATETIME('now')),
                    [userid] INTEGER NOT NULL,
                    [refresh_token] VARCHAR(1024) NOT NULL,
                    [status] INTEGER NOT NULL DEFAULT(1),
                    [ipaddr] VARCHAR(20)
                    );

                    CREATE TABLE IF NOT EXISTS [swagger] (
                    [id] INTEGER PRIMARY KEY ASC AUTOINCREMENT NOT NULL DEFAULT 1,
                    [username] VARCHAR(50) NOT NULL,
                    [password] VARCHAR(512) NOT NULL,
                    [status] INTEGER DEFAULT (1),
                    [lastaccess] DATETIME NOT NULL DEFAULT (DATETIME('now')),
                    [laststatus] INTEGER DEFAULT (200),
                    [lastipaddr] VARCHAR(20)
                    );

                    UPDATE [sqlite_sequence] SET seq = 1 WHERE name = 'swagger';

                    INSERT INTO swagger (username, password) VALUES ('admin', '"), PrepMySQLString(SimpleHash.ComputeHash("123456", "SHA256", null))), "');"));
                    cmd.CommandText = str_sql;
                    cmd.ExecuteNonQuery();
                    con.Close();
                }
                catch (Exception ex)
                {
                    WriteActivityLog(ex.Message, 2);
                    return false;
                }
                finally
                {
                    con.Close();
                }
            }

            try
            {
                con = new System.Data.SQLite.SQLiteConnection() { ConnectionString = mStrSQLiteConnString };
                con.Open();
                cmd.Connection = con;
                var dtB = con.GetSchema("Columns");
                if (dtB.Select("COLUMN_NAME = 'ipaddr' AND TABLE_NAME = 'tokens'").Length == 0)
                {
                    str_sql = "ALTER TABLE tokens ADD COLUMN [ipaddr] VARCHAR(20);";
                    cmd.CommandText = str_sql;
                    cmd.ExecuteNonQuery();
                }

                if (dtB.Select("COLUMN_NAME = 'name' AND TABLE_NAME = 'users'").Length == 0)
                {
                    str_sql = "ALTER TABLE users ADD COLUMN [name] VARCHAR(512);";
                    cmd.CommandText = str_sql;
                    cmd.ExecuteNonQuery();
                }

                if (dtB.Select("TABLE_NAME = 'validations'").Length == 0)
                {
                    str_sql = @"CREATE TABLE IF NOT EXISTS [validations] (
                    [id] INTEGER PRIMARY KEY ASC AUTOINCREMENT NOT NULL,
                    [date] DATETIME NOT NULL DEFAULT (DATETIME('now')),
                    [requestUri] TEXT,
                    [method] VARCHAR(20),
                    [status] INTEGER,
                    [statusMsg] TEXT,
                    [ipaddr] VARCHAR(20),
                    [userid] INTEGER,
                    [username] VARCHAR(50),
                    [role] VARCHAR(512),
                    [email] VARCHAR(512),
                    [nbf_date] VARCHAR(256),
                    [iat_date] VARCHAR(256),
                    [exp_date] VARCHAR(256),
                    [nbf] INTEGER,
                    [iat] INTEGER,
                    [exp] INTEGER,
                    [iss] VARCHAR(256),
                    [aud] VARCHAR(256),
                    [jti] VARCHAR(1024),
                    [token] TEXT
                    );";
                    cmd.CommandText = str_sql;
                    cmd.ExecuteNonQuery();
                    // con.Close()
                }

                if (dtB.Select("COLUMN_NAME = 'method' AND TABLE_NAME = 'validations'").Length == 0)
                {
                    str_sql = "ALTER TABLE validations ADD COLUMN [method] VARCHAR(20);";
                    cmd.CommandText = str_sql;
                    cmd.ExecuteNonQuery();
                    str_sql = @"CREATE TABLE IF NOT EXISTS [validationsbk] (
                    [id] INTEGER PRIMARY KEY ASC AUTOINCREMENT NOT NULL,
                    [date] DATETIME NOT NULL DEFAULT (DATETIME('now')),
                    [requestUri] TEXT,
                    [method] VARCHAR(20),
                    [status] INTEGER,
                    [statusMsg] TEXT,
                    [ipaddr] VARCHAR(20),
                    [userid] INTEGER,
                    [username] VARCHAR(50),
                    [role] VARCHAR(512),
                    [email] VARCHAR(512),
                    [nbf_date] VARCHAR(256),
                    [iat_date] VARCHAR(256),
                    [exp_date] VARCHAR(256),
                    [nbf] INTEGER,
                    [iat] INTEGER,
                    [exp] INTEGER,
                    [iss] VARCHAR(256),
                    [aud] VARCHAR(256),
                    [jti] VARCHAR(1024),
                    [token] TEXT
                    );";
                    cmd.CommandText = str_sql;
                    cmd.ExecuteNonQuery();
                    str_sql = @"INSERT INTO validationsbk
                            SELECT id,date,requestUri,method,status,statusMsg,ipaddr,userid,username,role,email,nbf_date,iat_date,exp_date,nbf,iat,exp,iss,aud,jti,token
                            FROM validations;";
                    cmd.CommandText = str_sql;
                    cmd.ExecuteNonQuery();
                    str_sql = @"DROP table validations;
                           ALTER TABLE validationsbk RENAME TO validations;";
                    cmd.CommandText = str_sql;
                    cmd.ExecuteNonQuery();
                }

                if (dtB.Select("TABLE_NAME = 'swagger'").Length == 0)
                {
                    str_sql = Conversions.ToString(Operators.ConcatenateObject(Operators.ConcatenateObject(@"CREATE TABLE IF NOT EXISTS [swagger] (
                    [id] INTEGER PRIMARY KEY ASC AUTOINCREMENT NOT NULL DEFAULT 1,
                    [username] VARCHAR(50) NOT NULL,
                    [password] VARCHAR(512) NOT NULL,
                    [status] INTEGER DEFAULT (1),
                    [lastaccess] DATETIME NOT NULL DEFAULT (DATETIME('now')),
                    [laststatus] INTEGER DEFAULT (200),
                    [lastipaddr] VARCHAR(20)
                    );

                    UPDATE [sqlite_sequence] SET seq = 1 WHERE name = 'swagger';

                    INSERT INTO swagger (username, password) VALUES ('admin', '", PrepMySQLString(SimpleHash.ComputeHash("123456", "SHA256", null))), "');"));
                    cmd.CommandText = str_sql;
                    cmd.ExecuteNonQuery();
                    // con.Close()
                }

                if (dtB.Select("TABLE_NAME = 'cardex_swagger'").Length == 0)
                {
                    str_sql = @"CREATE TABLE IF NOT EXISTS [cardex_swagger] (
                    [id] INTEGER PRIMARY KEY ASC AUTOINCREMENT NOT NULL,
                    [date] DATETIME NOT NULL DEFAULT (DATETIME('now')),
                    [requestUri] TEXT,
                    [status] INTEGER,
                    [statusMsg] TEXT,
                    [username] VARCHAR(50),
                    [ipaddr] VARCHAR(20)
                    );";
                    cmd.CommandText = str_sql;
                    cmd.ExecuteNonQuery();
                }

                if (dtB.Select("TABLE_NAME = 'params'").Length == 0)
                {
                    str_sql = @"CREATE TABLE IF NOT EXISTS [params] (
                    [id] INTEGER PRIMARY KEY ASC AUTOINCREMENT NOT NULL,
                    [swagAuth] INTEGER DEFAULT (0)
                    );

                    INSERT INTO params (swagAuth) VALUES (0);";
                    cmd.CommandText = str_sql;
                    cmd.ExecuteNonQuery();
                }

                con.Close();
            }
            catch (Exception ex)
            {
            }
            // If mBolAuto = False Then MsgBox("Error durante actualizacion de tablas" & vbCrLf & str_sql & vbCrLf & ex.Message)
            finally
            {
                con.Close();
            }

            return bolR;
        }

        public static User_Data QueryUserData(string strUser, int intType = 0)
        {
            var resP = new User_Data()
            {
                email = string.Empty,
                msg = string.Empty,
                passHash = string.Empty,
                role = string.Empty,
                status = false,
                user = string.Empty,
                userid = 0,
                valid = 0.ToString()
            };
            try
            {
                if (!string.IsNullOrEmpty(strUser))
                    strUser = strUser.ToLower();
                string strSQLQuery = @"
SELECT id, username, password, email, role, status
FROM users
WHERE lower(username) = @username
";
                if (intType == 1)
                {
                    strSQLQuery = "SELECT id, username, password, email, role, status FROM users WHERE id = @username";
                }

                using (var connection = new System.Data.SQLite.SQLiteConnection(mStrSQLiteConnString))
                {
                    using (var command = new System.Data.SQLite.SQLiteCommand(strSQLQuery, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.Parameters.Add(new System.Data.SQLite.SQLiteParameter("@username", strUser));
                        connection.Open();
                        using (var reader = command.ExecuteReader())
                        {
                            if (reader.HasRows)
                            {
                                while (reader.Read())
                                {
                                    resP.userid = Conversions.ToInteger(reader[0]);
                                    resP.user = reader[1].ToString();
                                    resP.passHash = reader[2].ToString();
                                    resP.email = reader[3].ToString();
                                    resP.role = reader[4].ToString();
                                    resP.valid = reader[5].ToString();
                                    resP.msg = reader.FieldCount.ToString();
                                }
                            }
                        }

                        resP.status = true;
                    }
                }
            }
            catch (Exception ex)
            {
                resP.status = false;
                resP.msg = ex.Message;
            }

            return resP;
        }

        public static bool AddCardexTokens(string uri, string method, int status, string statusMsg, string ip, string token)
        {
            bool bolR;
            try
            {
                Create_db();
                bolR = false;
                var lastaccess = DateTime.UtcNow;
                var tk = new Token_Extracted_Data();
                tk = ExtractTokenData(token);
                string jti = tk.jti;
                string userid = tk.userid.ToString();
                string username = tk.username;
                string role = tk.role;
                string email = tk.email;
                ulong nbf = Conversions.ToULong(tk.nbf);
                ulong iat = Conversions.ToULong(tk.iat);
                ulong exp = Conversions.ToULong(tk.exp);
                string iss = tk.iss;
                string aud = tk.aud;
                string nbf_date = tk.nbf_date;
                string iat_date = tk.iat_date;
                string exp_date = tk.exp_date;
                string strSQLQuery = @"INSERT INTO validations
(requestUri, method, status, statusMsg, ipaddr, userid, username, role, email, nbf_date, iat_date, exp_date, iss, aud, nbf, iat, exp, jti, token)
VALUES
(@requestUri, @method, @status, @statusMsg, @ipaddr, @userid, @username, @role, @email, @nbf_date, @iat_date, @exp_date, @iss, @aud, @nbf, @iat, @exp, @jti, @token);
UPDATE users SET lastaccess = @lastaccess, laststatus = @status, lastipaddr = @ipaddr WHERE id = @userid;";
                using (var connection = new System.Data.SQLite.SQLiteConnection(mStrSQLiteConnString))
                {
                    using (var command = new System.Data.SQLite.SQLiteCommand(strSQLQuery, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.Parameters.Add("@requestUri", DbType.String);
                        command.Parameters["@requestUri"].Value = uri;
                        command.Parameters.Add("@method", DbType.String);
                        command.Parameters["@method"].Value = method;
                        command.Parameters.Add("@status", DbType.Int32);
                        command.Parameters["@status"].Value = status;
                        command.Parameters.Add("@statusMsg", DbType.String);
                        command.Parameters["@statusMsg"].Value = statusMsg;
                        command.Parameters.Add("@ipaddr", DbType.String);
                        command.Parameters["@ipaddr"].Value = ip;
                        command.Parameters.Add("@userid", DbType.String);
                        command.Parameters["@userid"].Value = userid;
                        command.Parameters.Add("@username", DbType.String);
                        command.Parameters["@username"].Value = username;
                        command.Parameters.Add("@role", DbType.String);
                        command.Parameters["@role"].Value = role;
                        command.Parameters.Add("@email", DbType.String);
                        command.Parameters["@email"].Value = email;
                        command.Parameters.Add("@nbf_date", DbType.String);
                        command.Parameters["@nbf_date"].Value = nbf_date;
                        command.Parameters.Add("@iat_date", DbType.String);
                        command.Parameters["@iat_date"].Value = iat_date;
                        command.Parameters.Add("@exp_date", DbType.String);
                        command.Parameters["@exp_date"].Value = exp_date;
                        command.Parameters.Add("@iss", DbType.String);
                        command.Parameters["@iss"].Value = iss;
                        command.Parameters.Add("@aud", DbType.String);
                        command.Parameters["@aud"].Value = aud;
                        command.Parameters.Add("@nbf", DbType.UInt64);
                        command.Parameters["@nbf"].Value = nbf;
                        command.Parameters.Add("@iat", DbType.UInt64);
                        command.Parameters["@iat"].Value = iat;
                        command.Parameters.Add("@exp", DbType.UInt64);
                        command.Parameters["@exp"].Value = exp;
                        command.Parameters.Add("@jti", DbType.String);
                        command.Parameters["@jti"].Value = jti;
                        command.Parameters.Add("@token", DbType.String);
                        command.Parameters["@token"].Value = token;
                        command.Parameters.Add("@lastaccess", DbType.DateTime);
                        command.Parameters["@lastaccess"].Value = lastaccess;
                        connection.Open();
                        command.ExecuteNonQuery();
                        connection.Close();
                    }
                }

                bolR = true;
            }
            catch (Exception ex)
            {
                WriteActivityLog(ex.Message, 2);
                bolR = false;
            }

            return bolR;
        }

        public static bool AddSwaggerCardex(string uri, int status, string statusMsg, string ip, string username)
        {
            bool bolR;
            try
            {
                Create_db();
                bolR = false;
                var lastaccess = DateTime.UtcNow;
                string strSQLQuery = @"INSERT INTO cardex_swagger
(requestUri, status, statusMsg, ipaddr,username)
VALUES
(@requestUri, @status, @statusMsg, @ipaddr, @username);";
                using (var connection = new System.Data.SQLite.SQLiteConnection(mStrSQLiteConnString))
                {
                    using (var command = new System.Data.SQLite.SQLiteCommand(strSQLQuery, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.Parameters.Add("@requestUri", DbType.String);
                        command.Parameters["@requestUri"].Value = uri;
                        command.Parameters.Add("@status", DbType.Int32);
                        command.Parameters["@status"].Value = status;
                        command.Parameters.Add("@statusMsg", DbType.String);
                        command.Parameters["@statusMsg"].Value = statusMsg;
                        command.Parameters.Add("@ipaddr", DbType.String);
                        command.Parameters["@ipaddr"].Value = ip;
                        command.Parameters.Add("@username", DbType.String);
                        command.Parameters["@username"].Value = username;
                        connection.Open();
                        command.ExecuteNonQuery();
                        connection.Close();
                    }
                }

                bolR = true;
            }
            catch (Exception ex)
            {
                WriteActivityLog(ex.Message, 2);
                bolR = false;
            }

            return bolR;
        }

        public static Token_Extracted_Data ExtractTokenData(string strToken)
        {
            var tk = new Token_Extracted_Data();
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var handler = new JwtSecurityTokenHandler();
            try
            {
                JwtSecurityToken jwtToken = handler.ReadToken(strToken) as JwtSecurityToken;
                tk.jti = jwtToken.Claims.First(claim => claim.Type == "jti").Value;
                tk.userid = Conversions.ToInteger(jwtToken.Claims.First(claim => claim.Type == "userid").Value);
                tk.username = jwtToken.Claims.First(claim => claim.Type == "user").Value;
                tk.role = jwtToken.Claims.First(claim => claim.Type == "role").Value;
                tk.email = jwtToken.Claims.First(claim => claim.Type == "email").Value;
                tk.nbf = Conversions.ToDouble(jwtToken.Claims.First(claim => claim.Type == "nbf").Value);
                tk.iat = Conversions.ToDouble(jwtToken.Claims.First(claim => claim.Type == "iat").Value);
                tk.exp = Conversions.ToDouble(jwtToken.Claims.First(claim => claim.Type == "exp").Value);
                tk.iss = jwtToken.Claims.First(claim => claim.Type == "iss").Value;
                tk.aud = jwtToken.Claims.First(claim => claim.Type == "aud").Value;
                var timeSpan = TimeSpan.FromSeconds(tk.nbf);
                tk.nbf_date = epoch.Add(timeSpan).ToString("yyyy-MM-dd HH:mm:ss");
                timeSpan = TimeSpan.FromSeconds(tk.iat);
                tk.iat_date = epoch.Add(timeSpan).ToString("yyyy-MM-dd HH:mm:ss");
                timeSpan = TimeSpan.FromSeconds(tk.exp);
                tk.exp_date = epoch.Add(timeSpan).ToString("yyyy-MM-dd HH:mm:ss");
            }
            catch (Exception ex)
            {
                WriteActivityLog(ex.Message, 2);
            }

            return tk;
        }

        /* TODO ERROR: Skipped RegionDirectiveTrivia */
        /// <summary>
    /// Reads fieldName from Data Reader. If fieldName is DbNull, returns String.Empty.
    /// </summary>
    /// <returns>Safely returns a string. No need to check for DbNull.</returns>
        public static string ReadNullAsEmptyString(this IDataReader reader, string fieldName)
        {
            try
            {
                if (Information.IsDBNull(reader[fieldName]))
                {
                    return string.Empty;
                }
                else
                {
                    return Conversions.ToString(reader[fieldName]);
                }

                return Conversions.ToString(false);
            }
            catch (Exception ex)
            {
                return Conversions.ToString(reader[fieldName]);
            }
        }

        /// <summary>
    /// Reads fieldOrdinal from Data Reader. If fieldOrdinal is DbNull, returns String.Empty.
    /// </summary>
    /// <returns>Safely returns a string. No need to check for DbNull.</returns>
        public static string ReadString(this IDataReader reader, int fieldOrdinal)
        {
            if (Information.IsDBNull(reader[fieldOrdinal]))
            {
                return "";
            }
            else
            {
                return Conversions.ToString(reader[fieldOrdinal]);
            }

            return Conversions.ToString(false);
        }

        public static object PrepMySQLString(string str)
        {
            if (string.IsNullOrEmpty(str))
                str = string.Empty;
            return str;
        }

        /* TODO ERROR: Skipped EndRegionDirectiveTrivia */
    }

    public class JWT_Data
    {
        public string JWT_SQL_SERVER { get; set; }
        public string JWT_SQLITE_PASSWORD { get; set; }
        public string JWT_SECRET_KEY { get; set; }
        public string JWT_ISSUER_TOKEN { get; set; }
        public string JWT_AUDIENCE_TOKEN { get; set; }
        public int JWT_EXPIRE_MINUTES { get; set; }
    }

    public class User_Data
    {
        public int userid { get; set; }
        public string user { get; set; }
        public string passHash { get; set; }
        public string email { get; set; }
        public string role { get; set; }
        public string valid { get; set; }
        public bool status { get; set; }
        public string msg { get; set; }
    }

    public class JSON_Token_ResponseError
    {
        public string error { get; set; }
        public string msg { get; set; }
    }

    public class JSON_Token_Response
    {
        public string access_token { get; set; }
        public string refresh_token { get; set; }
        public string token_type { get; set; }
        public int expires_in { get; set; }
        public string userName { get; set; }
        public string issued { get; set; }
        public string expires { get; set; }
    }

    public class Token_Extracted_Data
    {
        public string jti { get; set; }
        public int userid { get; set; }
        public string username { get; set; }
        public string role { get; set; }
        public string email { get; set; }
        public double nbf { get; set; }
        public double iat { get; set; }
        public double exp { get; set; }
        public string iss { get; set; }
        public string aud { get; set; }
        public string nbf_date { get; set; }
        public string iat_date { get; set; }
        public string exp_date { get; set; }
    }
}