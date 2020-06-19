use super::controller::DITTO_VERSION;

pub fn nginx_conf(name: String, swagger_ui: bool) -> String {
    let mut result = String::new();

    result += r#"
worker_processes 1;
pid /run/nginx/nginx.pid;

events {worker_connections 1024;}
"#;

    result += r#"
http {
  charset utf-8;
  default_type application/json;
  include mime.types;

  # timeouts are configured slightly higher than ditto-eclipse-ditto-gateway read-timeout of 60 seconds
  proxy_connect_timeout 70; # seconds, default: 60
  proxy_send_timeout 70; # seconds, default: 60
  proxy_read_timeout 70; # seconds, default: 60
  send_timeout 70; # seconds, default: 60

  client_header_buffer_size 8k; # allow longer URIs + headers (default: 1k)
  large_client_header_buffers 4 16k;

  merge_slashes off; # allow multiple slashes for CRS Authentication
"#;

    result += format!(
        r#"
  upstream {name}-gateway {{
    server {name}-gateway:8080;
  }}
"#,
        name = name
    )
    .as_str();

    result += r#"

  server {
    listen 8080;
    server_name localhost;

    location / {
      index index.html;
    }

"#;

    result += format!(
        r#"
    # api
    location /api {{
      include nginx-cors.conf;
      auth_basic                    "Authentication required";
      auth_basic_user_file          nginx.htpasswd;
      proxy_set_header              X-Forwared-User     $remote_user;
      proxy_set_header              x-ditto-dummy-auth  "nginx:${{remote_user}}";
    
      proxy_pass                    http://{name}-gateway;
      proxy_http_version            1.1;
      proxy_set_header              Host                $http_host;
      proxy_set_header              X-Real-IP           $remote_addr;
      proxy_set_header              X-Forwarded-For     $proxy_add_x_forwarded_for;

      proxy_set_header Connection  '';
      chunked_transfer_encoding    off;
      proxy_buffering              off;
      proxy_cache                  off;
    }}

    # ws
    location /ws {{
      auth_basic                    "Authentication required";
      auth_basic_user_file          nginx.htpasswd;
      proxy_set_header              X-Forwared-User     $remote_user;
      proxy_set_header              x-ditto-dummy-auth  "nginx:${{remote_user}}";
      
      proxy_pass                    http://{name}-gateway;
      proxy_http_version            1.1;
      proxy_set_header              Host                $http_host;
      proxy_set_header              X-Real-IP           $remote_addr;
      proxy_set_header              X-Forwarded-For     $proxy_add_x_forwarded_for;

      proxy_set_header              Upgrade             $http_upgrade;
      proxy_set_header              Connection          "upgrade";
      proxy_read_timeout            1d;
      proxy_send_timeout            1d;
    }}

    # health
    location /health {{
      include nginx-cors.conf;

      proxy_pass                    http://{name}-gateway/health;
      proxy_http_version            1.1;
      proxy_set_header              Host                $http_host;
      proxy_set_header              X-Real-IP           $remote_addr;
      proxy_set_header              X-Forwarded-For     $proxy_add_x_forwarded_for;
      proxy_set_header              X-Forwarded-User    $remote_user;
    }}

    # status
    location /status {{
      include nginx-cors.conf;

      proxy_pass                    http://{name}-gateway/overall/status;
      proxy_http_version            1.1;
      proxy_set_header              Host                $http_host;
      proxy_set_header              X-Real-IP           $remote_addr;
      proxy_set_header              X-Forwarded-For     $proxy_add_x_forwarded_for;
      proxy_set_header              X-Forwarded-User    $remote_user;
    }}
    # stats
    location /stats {{
      include nginx-cors.conf;
      proxy_pass                    http://{name}-gateway/stats;
      proxy_http_version            1.1;
      proxy_set_header              Host                $http_host;
      proxy_set_header              X-Real-IP           $remote_addr;
      proxy_set_header              X-Forwarded-For     $proxy_add_x_forwarded_for;
      proxy_set_header              X-Forwarded-User    $remote_user;
    }}

    # devops
    location /devops {{
      include nginx-cors.conf;
      proxy_pass                    http://{name}-gateway/devops;
      proxy_http_version            1.1;
      proxy_set_header              Host                $http_host;
      proxy_set_header              X-Real-IP           $remote_addr;
      proxy_set_header              X-Forwarded-For     $proxy_add_x_forwarded_for;
      proxy_set_header              X-Forwarded-User    $remote_user;
    }}
"#,
        name = name
    )
    .as_str();

    if swagger_ui {
        result += format!(r#"
    # swagger
    # access API doc on: /apidoc/1 or /apidoc/2
    location /apidoc/ {{
      rewrite ^/apidoc/([0-9])$ $http_x_forwarded_proto://$http_host/apidoc/?url=/ditto-api-v$1.yaml redirect;
      proxy_pass                    http://{name}-swaggerui:8080/;
      proxy_http_version            1.1;
      proxy_set_header              Host                $http_host;
    }}
        "#,
            name=name,
        ).as_str();
    }

    result += r#"
  }
}
"#;

    return result;
}
