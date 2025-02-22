---
title: authz-keycloak
---

<!--
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
-->

## 描述

目前 `authz-plugin` 仅支持通过定义资源名和访问权限范畴来应用 `route` 的访问策略。但是 Keycloak 官方适配的其他语言的客户端 (Java, JS) 还可以通过动态查询 Keycloak 路径以及懒加载身份资源的路径来支持路径匹配。未来版本的 `authz-plugin` 将会支持这项功能。

## 属性

| 名称                        | 类型          | 必选项 | 默认值      | 有效值                      | 描述                                                                                            |
| -----------------------     | ------------- | ------ | ----------- | --------------------------- | ----------------------------------------------------------------------------------------------- |
| token_endpoint              | string        | 必须   |             |                              | 接受 OAuth2 兼容 token 的接口，需要支持 `urn:ietf:params:oauth:grant-type:uma-ticket` 授权类型  |
| grant_type                  | string        | 可选   | "urn:ietf:params:oauth:grant-type:uma-ticket" | ["urn:ietf:params:oauth:grant-type:uma-ticket"] |                                    |
| audience                    | string        | 可选   |             |                             | 客户端应用访问相应的资源服务器时所需提供的身份信息。当 permissions 参数有值时这个参数是必填的。 |
| permissions                 | array[string] | 可选   |             |                             | 描述客户端应用所需访问的资源和权限范围的字符串。格式必须为：`RESOURCE_ID#SCOPE_ID`              |
| timeout                     | integer       | 可选   | 3000        | [1000, ...]                 | 与身份认证服务器的 http 连接的超时时间                                                          |
| access_token_expires_in     | integer       | 可选   | 300         | [1, ...]                            | access token 的过期时间(秒)
| access_token_expires_leeway | integer       | 可选   | 0           | [0, ...]                            | access token 提前更新时间（秒，如果设置了此值，允许在该时间段内使用相同的 access token 令牌来解决潜在的网络并发问题）        |
| refresh_token_expires_in    | integer       | 可选   | 3600        | [1, ...]                            | refresh token 的过期时间(秒)                                                                               |
| refresh_token_expires_leeway| integer       | 可选   | 0           | [0, ...]                            | refresh token 提前更新时间（秒，如果设置了此值，允许在该时间段内使用相同的 refresh token 令牌来解决潜在的网络并发问题）                                                                   |
| ssl_verify                  | boolean       | 可选   | true        | [0, ...]                            | 验证 SSL 证书与主机名是否匹配                                                                   |
| policy_enforcement_mode     | string        | 可选   | "ENFORCING" | ["ENFORCING", "PERMISSIVE"] |                                                                                                 |
| access_denied_redirect_uri  | string        | 可选   |             | [1, 2048]                           |未授权的用户不会返回 `"error_description":"not_authorized"`，而是会定重定向至给定的 uri，如 "http://127.0.0.1/test"
|

### 策略执行模式

定义了在处理身份认证请求时如何应用策略

**Enforcing**

- （默认）如果资源没有绑定任何访问策略，请求默认会被拒绝。

**Permissive**

- 如果资源没有绑定任何访问策略，请求会被允许。

## 如何启用

创建一个 `route` 对象，并在该 `route` 对象上启用 `authz-keycloak` 插件, `${realm}` 是 `Keycloak` 中的 `realm` 名称：

```shell
curl http://127.0.0.1:9080/apisix/admin/routes/5 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
    "uri": "/get",
    "plugins": {
        "authz-keycloak": {
            "token_endpoint": "http://127.0.0.1:8090/auth/realms/${realm}/protocol/openid-connect/token",
            "permissions": ["resource name#scope name"],
            "audience": "Client ID"
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "127.0.0.1:8080": 1
        }
    }
}'
```

## 测试插件

获取 `{JWT Token}`

```shell
curl \
  -d "client_id=<YOUR_CLIENT_ID>" \
  -d "username=<YOUR_USERNAMED>" \
  -d "password=<YOUR_PASSWORD>" \
  -d "grant_type=password" \
  "http://<YOUR_KEYCLOAK_HOST>/auth/realms/${realm}/protocol/openid-connect/token"
```

验证

```shell
curl http://127.0.0.1:9080/get -H 'Authorization: Bearer {JWT Token}'
```

## 禁用插件

在插件设置页面中删除相应的 json 配置即可禁用 `authz-keycloak` 插件。APISIX 的插件是热加载的，因此无需重启 APISIX 服务。

```shell
curl http://127.0.0.1:9080/apisix/admin/routes/5 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
    "uri": "/get",
    "plugins": {
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "127.0.0.1:8080": 1
        }
    }
}'
```

## 示例

请查看 authz-keycloak.t 中的单元测试来了解如何将身份认证策略与您的 API 工作流集成。运行以下 docker 镜像并访问 `http://localhost:8090` 来查看单元测试中绑定的访问策略：

```bash
docker run -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=123456 -p 8090:8080 sshniro/keycloak-apisix
```

下面这张截图显示了如何在 Keycloak 服务器上配置访问策略：

![Keycloak policy design](../../../assets/images/plugin/authz-keycloak.png)

## 后续开发

- 目前 `authz-plugin` 仅支持通过定义资源名和访问权限范畴来应用 `route` 的访问策略。但是 Keycloak 官方适配的其他语言的客户端 (Java, JS) 还可以通过动态查询 Keycloak
  路径以及懒加载身份资源的路径来支持路径匹配。未来版本的 `authz-plugin` 将会支持这项功能。

- 支持从 Keycloak JSON 文件中读取权限范畴和其他配置项。
