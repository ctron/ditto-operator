/*
 * Copyright (c) 2020, 2021 Red Hat Inc.
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */

pub fn nginx_conf<N: AsRef<str>>(
    name: N,
    swagger_ui: bool,
    oauth2: bool,
    expose_infra: bool,
    expose_devops: bool,
    welcome: bool,
) -> String {
    let name = name.as_ref();

    let mut result = String::new();

    result += "# Automatically generated by the ditto-operator\n";

    let basic_auth = match oauth2 {
        // allow pre-auth
        false => {
            r#"
      auth_basic                    "Authentication required";
      auth_basic_user_file          nginx.htpasswd;
      proxy_set_header              X-Forwared-User     $remote_user;
      proxy_set_header              x-ditto-pre-authenticated  "nginx:${remote_user}";
"#
        }
        // prevent external injection of pre-auth
        true => "",
    };

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

  types {
    application/x-yaml    yaml;
  }

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

"#;

    if welcome {
        result += r#"
    location / {
      index index.html index.default.html;
    }
"#;
    } else {
        result += r#"
    location / {
      index index.json;
    }
"#;
    }

    result += format!(
        r#"
    # api
    location /api {{
      include nginx-cors.conf;

{basic_auth}

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

{basic_auth}

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
"#,
        name = name,
        basic_auth = basic_auth
    )
    .as_str();

    if expose_infra {
        result += format!(
            r#"
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
    "#,
            name = name,
        )
        .as_str();
    } else {
        result += r#"
    # health
    location ^~ /health/ {
      return 404;
    }
"#;
    }

    if expose_devops {
        result += r#"
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
"#;
    }

    if oauth2 {
        result += format!(
            r#"
    # oauth2
    location /oauth2 {{
      include nginx-cors.conf;
      proxy_pass                    http://{name}-gateway/oauth2;
      proxy_http_version            1.1;
      proxy_set_header              Host                $http_host;
      proxy_set_header              X-Real-IP           $remote_addr;
      proxy_set_header              X-Forwarded-For     $proxy_add_x_forwarded_for;
      proxy_set_header              X-Forwarded-User    $remote_user;
    }}
"#,
            name = name,
        )
        .as_str();
    }

    if swagger_ui {
        if oauth2 {
            result += r#"
    # redirect oauth2 result URL to the redirected swagger UI space
    location /oauth2-redirect.html {
      rewrite ^/oauth2-redirect.html$ $http_x_forwarded_proto://$http_host/apidoc/oauth2-redirect.html redirect;
    }
"#;
        }

        result += format!(r#"
    # swagger
    # access API doc on: /apidoc/2
    location /apidoc/ {{
      rewrite ^/apidoc/([0-9])$ $http_x_forwarded_proto://$http_host/apidoc/?url=/apidoc/openapi/ditto-api-v$1.yaml redirect;
      proxy_pass                    http://{name}-swaggerui:8080/;
      proxy_http_version            1.1;
      proxy_set_header              Host                $http_host;
    }}
"#,
                              name = name,
            ).as_str();
    }

    result += r#"
  }
}
"#;

    result
}

/// Provide the default index.html file
pub fn nginx_default(oauth: bool, swagger: bool, expose_infra: bool) -> String {
    let html = include_str!("../resources/index.html");

    let login = match oauth {
        true => {
            r#"<p>
                Try out the HTTP APIs by logging in to Keycloak using the <code>Authorize</code> button in the Swagger UI, or by providing a valid OAuth token to your requests.
            </p>"#
        }
        false => {
            r#"<p>
                Try out the HTTP APIs by using username "ditto" and password "ditto" when asked for by your browser.
            </p>"#
        }
    };

    let html = html.replace("@@LOGIN@@", login);

    let html = html.replace(
        "@@SWAGGER@@",
        match swagger {
            true => r#"
        <p>In order to get started quickly and if you started the local Swagger UI, you can now have a look at the OpenAPI documentation for
        <ul>
            <li><a href="/apidoc/2">API version 2</a></li>
        </ul>"#,
            false => "",
        },
    );

    let html = html.replace(
        "@@HEALTH_HTML@@",
        match expose_infra {
            true => {
                r#"
    <h2 style="clear: both">Health</h2>
    <div id="health-content">
    </div>
    <h2>Statistics</h2>
    <div>
        <div class="stats">
            <span id="total-things-count" class="stats-count"></span><span
                class="stats-count-text"> persisted <em>Things</em></span>
        </div>
        <div class="stats">
            <span id="hot-things-count" class="stats-count"></span><span class="stats-count-text"> currently "hot" <em>Things</em> (accessed within the last 2 hours)</span>
        </div>
    </div>
"#
            }
            false => "",
        },
    );
    let html = html.replace(
        "@@HEALTH_JS@@",
        match expose_infra {
            true => r#"<script>fetchHealth()</script>"#,
            false => "",
        },
    );

    html
}
