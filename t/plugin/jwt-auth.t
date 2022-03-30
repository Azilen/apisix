#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
use t::APISIX 'no_plan';

repeat_each(2);
no_long_string();
no_root_location();
no_shuffle();

__DATA__
=== TEST 52: inject jwt token payload
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1',
                 ngx.HTTP_PUT,
                 [[{
                        "plugins": {
                            "authz-keycloak": {
                                "token_endpoint": "https://127.0.0.1:8443/auth/realms/University/protocol/openid-connect/token",
                                "permissions": ["course_resource#view"],
                                "client_id": "course_management",
                                "client_secret": "d1ec69e9-55d2-4109-a3ea-befa071579d5",
                                "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
                                "timeout": 3000,
                                "ssl_verify": false,
                                "password_grant_token_generation_incoming_uri": "/api/token"
                            }
                        },
                        "upstream": {
                            "nodes": {
                                "127.0.0.1:1982": 1
                            },
                            "type": "roundrobin"
                        },
                        "uri": "/api/token"
                }]]
            )

            if code >= 300 then
                ngx.status = code
            end

            local json_decode = require("toolkit.json").decode
            local http = require "resty.http"
            local httpc = http.new()
            local uri = "http://127.0.0.1:" .. ngx.var.server_port .. "/api/token"
            local res, err = httpc:request_uri(uri, {
                method = "POST",
                headers = {
                    ["Content-Type"] = "application/x-www-form-urlencoded",
                },

                body =  ngx.encode_args({
                    username = "user@gmail.com",
                    password = "123456",
                }),
            })

            if res.status == 200 then
                local body = json_decode(res.body)
                local accessToken = body["access_token"]
                local refreshToken = body["refresh_token"]

                if accessToken and refreshToken then
                    local jwt = require("resty.jwt")
                    local jwt_obj = jwt:load_jwt(accessToken)
    
                    if not jwt_obj.valid then
                        ngx.status = 401
                        ngx.say(jwt_obj.reason)
                        return
                    end

                    local user_key = jwt_obj.payload and jwt_obj.payload.key
                    if not user_key then
                        ngx.status = 401
                        ngx.say("missing user key in JWT token")
                        return
                    end

                    local code, body = t('/apisix/admin/consumers',
                    ngx.HTTP_PUT,
                    [[{
                        "username": "azilen",
                        "plugins": {
                            "jwt-auth": {
                                "key": user_key,
                                "algorithm": "RS256",
                                "public_key": "-----BEGIN PUBLIC KEY-----\n PublicKey \n-----END PUBLIC KEY-----",
                                "access_token_payload_header_name": "X-User-Info",
                                "inject_access_token_payload_in_request": true
                            }
                        }
                    }]]
                    )
                    ngx.status = code
                    if code > 200 then
                        ngx.status = 401
                        ngx.say("Missing related consumer")
                        return
                    end

                    if not jwt_obj.verified then
                        ngx.status = 401
                        ngx.say(jwt_obj.reason)
                        return
                    end

                    local consumer= json_decode(body)

                    local inject_access_token_payload = consumer.auth_conf.inject_access_token_payload_in_request and 
                    consumer.auth_conf.access_token_payload_header_name
                    if inject_access_token_payload then
                       ngx.header[consumer.auth_conf.access_token_payload_header_name]= json_encode(jwt_obj.payload)
                    end
                    ngx.say(true)
                else
                    ngx.say(false)
                end
            else
                ngx.say(false)
            end
        }
    }
--- request
GET /t
--- response_body
true
--- no_error_log
[error]