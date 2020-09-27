using System;
using System.Linq;
using System.IO;
using System.Collections.Generic;

namespace GdP
{
    class Program
    {
        private static Random random = new Random();
        private const int PASSWORD_LENGTH = 8;
        private const string URL_BASE = "/eq";

        static void Main(string[] args)
        {
            int nbInstances;
            string password, noderedConfig, baseDirectory, docker_start, padded_i;
            List<string> nginx_locations = new List<string>();
            List<string> nginx_upstreams = new List<string>();

            Console.WriteLine("Nombre d'instances à générer ?");
            nbInstances = int.Parse(Console.ReadLine());

            // Directory init
            if (Directory.Exists("./config"))
                Directory.Delete("./config", true);

            Directory.CreateDirectory("./config");
            Directory.CreateDirectory("./config/nginx");
            Directory.CreateDirectory("./config/mosquitto");

            // docker_create.sh init
            File.WriteAllText("./config/create.sh", "#!/bin/bash\nsudo chown -R 1000:1000 ./eq*\n");
            File.WriteAllText("./config/rm.sh", "#!/bin/bash\nsudo rm eq* -rd\n");
            File.WriteAllText("./config/stop.sh", "#!/bin/bash\n");
            File.WriteAllText("./config/start.sh", "#!/bin/bash\n");

            File.Copy("./mosquitto.conf", "./config/mosquitto/mosquitto.conf");
            File.WriteAllText("./config/mosquitto/acl", "user admin\ntopic #\n");

            for (int i = 1; i <= nbInstances; i++)
            {
                password = RandomString(PASSWORD_LENGTH);
                padded_i = i < 10 ? "0" + i.ToString() : i.ToString();

                baseDirectory = "./config/eq" + padded_i;
                Directory.CreateDirectory(baseDirectory);

                // Node red config
                noderedConfig = GenerateNoderedConfig(BCrypt.Net.BCrypt.HashPassword(password), padded_i);
                File.WriteAllText(baseDirectory + "/settings.js", noderedConfig);

                // Mosquitto config
                File.AppendAllText("./config/password", String.Format("eq{0}:{1}\n", padded_i, password));
                File.AppendAllText("./config/mosquitto/password", String.Format("eq{0}:{1}\n", padded_i, password));
                File.AppendAllText("./config/mosquitto/acl", $"user eq{padded_i}\ntopic eq{padded_i}/#\n\n");

                // Docker file
                docker_start = $"docker run -itd --network gdp -v /home/theophile/config/eq{padded_i}:/data --name nodered_eq{padded_i} nodered/node-red";
                File.AppendAllText("./config/create.sh", docker_start + "\n");
                File.AppendAllText("./config/stop.sh", "docker stop nodered_eq" + padded_i + "\n");
                File.AppendAllText("./config/start.sh", "docker start nodered_eq" + padded_i + "\n");
                File.AppendAllText("./config/rm.sh", "docker rm nodered_eq" + padded_i + "\n");

                // Nginx config
                nginx_locations.Add($"\tlocation /eq{padded_i}{{\n\t\tproxy_pass http://nodered_eq{padded_i};\n\t}}");
                nginx_upstreams.Add($"upstream nodered_eq{padded_i} {{\n\tserver nodered_eq{padded_i}:1880;\n}}");
            }

            File.AppendAllText("./config/create.sh", "docker run -itd -p 80:80 -p 443:443 -v /home/theophile/config/nginx:/etc/nginx/conf.d:ro -v /home/theophile/certs:/etc/nginx/certs:ro --network gdp --name nginx_gdp nginx\n");
            File.AppendAllText("./config/create.sh", "mosquitto_passwd -U mosquitto/password\n");
            File.AppendAllText("./config/create.sh", "mosquitto_passwd -b mosquitto/password admin esilvGdP\n");
            File.AppendAllText("./config/create.sh", "sed -i '1s/^\\xEF\\xBB\\xBF//' mosquitto/mosquitto.conf\n");
            File.AppendAllText("./config/create.sh", "docker run -itd -p 1883:1883 -v /home/theophile/config/mosquitto:/mosquitto/config --network gdp --name mqtt eclipse-mosquitto\n");
            File.AppendAllText("./config/stop.sh", "docker stop nginx_gdp\ndocker stop mqtt\n");
            File.AppendAllText("./config/start.sh", "docker start nginx_gdp\ndocker start mqtt\n");
            File.AppendAllText("./config/rm.sh", "docker rm nginx_gdp\ndocker rm mqtt\n");

            File.WriteAllText("./config/nginx/default.conf", GenerateNginxConfig(nginx_upstreams, nginx_locations));
        }

        static string GenerateNginxConfig(List<string> nginx_upstreams, List<string> nginx_locations)
        {
            return $@"{nginx_upstreams.Aggregate((i,j) => i + "\n" + j)}
server {{
    listen 80;
    server_name gdp.devinci.fr;
    return 301 https://gdp.devinci.fr$request_uri;
}}

server {{
    listen 443 ssl;
    server_name gdp.devinci.fr;

    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
 
    proxy_http_version  1.1;

	#Sets conditions under which the response will not be taken from a cache.
	proxy_cache_bypass  $http_upgrade;

	#These header fields are required if your application is using Websockets
	proxy_set_header Upgrade $http_upgrade;

	#These header fields are required if your application is using Websockets    
	proxy_set_header Connection ""upgrade"";

    # The $host variable in the following order of precedence contains:
    # hostname from the request line, or hostname from the Host request header field
    # or the server name matching a request.    
    proxy_set_header Host $host;
    { nginx_locations.Aggregate((i, j) => i + "\n" + j)}
}}";
        }

        static string GenerateNoderedConfig(string password, string eqNb)
        {
            return String.Format(
                @"
module.exports = {{
    // the tcp port that the Node-RED web server is listening on
    uiPort: process.env.PORT || 1880,

    // By default, the Node-RED UI accepts connections on all IPv4 interfaces.
    // To listen on all IPv6 addresses, set uiHost to ""::"",
    // The following property can be used to listen on a specific interface. For
    // example, the following would only allow connections from the local machine.
    //uiHost: ""127.0.0.1"",

    // Retry time in milliseconds for MQTT connections
    mqttReconnectTime: 15000,

    // Retry time in milliseconds for Serial port connections
    serialReconnectTime: 15000,

    // Retry time in milliseconds for TCP socket connections
    //socketReconnectTime: 10000,

    // Timeout in milliseconds for TCP server socket connections
    //  defaults to no timeout
    //socketTimeout: 120000,

    // Maximum number of messages to wait in queue while attempting to connect to TCP socket
    //  defaults to 1000
    //tcpMsgQueueSize: 2000,

    // Timeout in milliseconds for HTTP request connections
    //  defaults to 120 seconds
    //httpRequestTimeout: 120000,

    // The maximum length, in characters, of any message sent to the debug sidebar tab
    debugMaxLength: 1000,

    // The maximum number of messages nodes will buffer internally as part of their
    // operation. This applies across a range of nodes that operate on message sequences.
    //  defaults to no limit. A value of 0 also means no limit is applied.
    //nodeMessageBufferMaxLength: 0,

    // To disable the option for using local files for storing keys and certificates in the TLS configuration
    //  node, set this to true
    //tlsConfigDisableLocalFiles: true,

    // Colourise the console output of the debug node
    //debugUseColors: true,

    // The file containing the flows. If not set, it defaults to flows_<hostname>.json
    //flowFile: 'flows.json',

    // To enabled pretty-printing of the flow within the flow file, set the following
    //  property to true:
    //flowFilePretty: true,

    // By default, credentials are encrypted in storage using a generated key. To
    // specify your own secret, set the following property.
    // If you want to disable encryption of credentials, set this property to false.
    // Note: once you set this property, do not change it - doing so will prevent
    // node-red from being able to decrypt your existing credentials and they will be
    // lost.
    //credentialSecret: ""a-secret-key"",

    // By default, all user data is stored in a directory called `.node-red` under
    // the user's home directory. To use a different location, the following
    // property can be used
    //userDir: '/home/nol/.node-red/',

    // Node-RED scans the `nodes` directory in the userDir to find local node files.
    // The following property can be used to specify an additional directory to scan.
    //nodesDir: '/home/nol/.node-red/nodes',

    // By default, the Node-RED UI is available at http://localhost:1880/
    // The following property can be used to specify a different root path.
    // If set to false, this is disabled.
    //httpAdminRoot: '/admin',

    // Some nodes, such as HTTP In, can be used to listen for incoming http requests.
    // By default, these are served relative to '/'. The following property
    // can be used to specifiy a different root path. If set to false, this is
    // disabled.
    //httpNodeRoot: '/red-nodes',

    // The following property can be used in place of 'httpAdminRoot' and 'httpNodeRoot',
    // to apply the same root to both parts.
    httpRoot: '{1}',

    // When httpAdminRoot is used to move the UI to a different root path, the
    // following property can be used to identify a directory of static content
    // that should be served at http://localhost:1880/.
    //httpStatic: '/home/nol/node-red-static/',

    // The maximum size of HTTP request that will be accepted by the runtime api.
    // Default: 5mb
    //apiMaxLength: '5mb',

    // If you installed the optional node-red-dashboard you can set it's path
    // relative to httpRoot
    //ui: {{ path: ""ui"" }},

    // Securing Node-RED
    // -----------------
    // To password protect the Node-RED editor and admin API, the following
    // property can be used. See http://nodered.org/docs/security.html for details.
    adminAuth: {{
        type: ""credentials"",
        users: [
        {{
            username: ""admin"",
            password: ""$2a$08$dLbbjTsj.ULx2O9PcPd8yuoegBSR.Q5rbc4g5vZsbx8CTAxjEB6vi"",
            permissions: ""*""
        }},
        {{
            username: ""eq{2}"",
            password: ""{0}"",
            permissions: ""*""
        }}]
    }},

    // To password protect the node-defined HTTP endpoints (httpNodeRoot), or
    // the static content (httpStatic), the following properties can be used.
    // The pass field is a bcrypt hash of the password.
    // See http://nodered.org/docs/security.html#generating-the-password-hash
    //httpNodeAuth: {{user:""user"",pass:""$2a$08$zZWtXTja0fB1pzD4sHCMyOCMYz2Z6dNbM6tl8sJogENOMcxWV9DN.""}},
    //httpStaticAuth: {{user:""user"",pass:""$2a$08$zZWtXTja0fB1pzD4sHCMyOCMYz2Z6dNbM6tl8sJogENOMcxWV9DN.""}},

    // The following property can be used to disable the editor. The admin API
    // is not affected by this option. To disable both the editor and the admin
    // API, use either the httpRoot or httpAdminRoot properties
    //disableEditor: false,

    // The following property can be used to configure cross-origin resource sharing
    // in the HTTP nodes.
    // See https://github.com/troygoode/node-cors#configuration-options for
    // details on its contents. The following is a basic permissive set of options:
    //httpNodeCors: {{
    //    origin: ""*"",
    //    methods: ""GET,PUT,POST,DELETE""
    //}},

    // The following property can be used to order the categories in the editor
    // palette. If a node's category is not in the list, the category will get
    // added to the end of the palette.
    // If not set, the following default order is used:
    //paletteCategories: ['subflows', 'common', 'function', 'network', 'sequence', 'parser', 'storage'],

    // Configure the logging output
    logging:
                {{
                // Only console logging is currently supported
                console:
                    {{
                    // Level of logging to be recorded. Options are:
                    // fatal - only those errors which make the application unusable should be recorded
                    // error - record errors which are deemed fatal for a particular request + fatal errors
                    // warn - record problems which are non fatal + errors + fatal errors
                    // info - record information about the general running of the application + warn + error + fatal errors
                    // debug - record information which is more verbose than info + info + warn + error + fatal errors
                    // trace - record very detailed logging + debug + info + warn + error + fatal errors
                    // off - turn off all logging (doesn't affect metrics or audit)
                    level: ""info"",
            // Whether or not to include metric events in the log output
            metrics: false,
            // Whether or not to include audit events in the log output
            audit: false
                }}
                }},

    // Customising the editor
    editorTheme:
                {{
                projects:
                    {{
                    // To enable the Projects feature, set this value to true
                    enabled: false
                }}
                }}
            }}
            ",
                password,
                URL_BASE + eqNb,
                eqNb);
        }

        public static string RandomString(int length)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}
