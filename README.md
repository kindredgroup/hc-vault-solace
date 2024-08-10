# Hashicorp Vault Solace plugin

This is custom secrets engine for Vault which generates dynamic credentials in Solace.

## Build, install and upgrade

Vault Docker images used for testing are based on Alpine Linux (musl), so they need an extra step to build the plugin.
```
[dev|pripii@priitp-roadkill ]$ mkdir $GOPATH/src/kindredgroup.com && cd $GOPATH/src/kindredgroup.com
[dev|pripii@priitp-roadkill kindredgroup.com]$ git clone https://github.com/kindredgroup/hc-vault-solace solace-plugin && cd solace-plugin
[dev|pripii@priitp-roadkill solace-plugin]$ podman run -i --rm -v `pwd`:/build -w /build golang:1.21.11-alpine go build -tags netgo,osusergo -v
```
This creates the file `solace-plugin` in the current directory.

### How to Register plugin in vault

Assuming that binary is copied to `/vault/plugins/solace-plugin`:
```
/ # sha256sum /vault/plugins/solace-plugin-v0.0.45
# Next is needed with official vault docker image
/ # setcap cap_ipc_lock=+ep /vault/plugins/solace-plugin-v0.0.45
/ # vault write sys/plugins/catalog/secret/solace-plugin sha256=<something-something> command="solace-plugin-v0.0.45"
/ # vault secrets enable secret/solace-plugin
```

### How to upgrade the plugin

Since plugin is versioned it can't be just installed, it has to be upgraded. As a bonus, if upgrade fails vault will fall back to the previous version of the plugin.
```
$PLUGIN="/vault/plugins/solace-plugin-v0.0.52"
$PLUGIN_VERSION="v0.0.45"
setcap cap_ipc_lock=+ep $PLUGIN
HASH=`sha256sum $PLUGIN|cut -d ' ' -f 1`
vault plugin register -sha256="$HASH" -command=solace-plugin-$PLUGIN_VERSION -version=$PLUGIN_VERSION secret solace-plugin
vault secrets enable solace-plugin
vault secrets tune -plugin-version=$PLUGIN_VERSION solace-plugin
vault plugin reload -plugin solace-plugin
```

## Plugin configuration

```
bash-5.0# export VAULT_ADDR='http://127.0.0.1:8200'
bash-5.0# vault write secret/solace-plugin/config/default host="localhost:8080,172.19.0.4:8080" username="admin" password=<something-something> disable_tls=true
```
Configuration item name is last part of the path, and it is mandatory. Hostname can be a comma separated list, in that case plugin checks whick Solace instance is the primary and sends requests to that instance.

|Parameter|Description|Mandatory|
----------|-----------|-----------
|host|<hostname/IP>:port,<hostname/IP>:port|Yes|
|username|Solace admin user|Yes|
|password|Admin user pwd|Yes|
|path|Rest of the SEMP URL|No, default: SEMP/v2/config|
|disable\_tls|host points to plain HTTP|No, default: false|

### List of configs
```
bash-5.0# vault list solace-plugin/configs
Keys
----
default
dev
```

## Roles

All parameters are mandatory exept acl\_profile, client\_profile, and subscription\_manager. Parameter
guaranteed\_endpoint\_permission\_override is hardcoded to true.  

```
bash-5.0# vault write solace-plugin/roles/testrole vpn=testvpn ttl=<duration> config\_name=default acl_profile=<acl profile from solace> client_profile= <client profile from Solace> username_prefix=slowBoring
Key     Value
---     -----
Ttl     600s
Vpn     testvpn
config_name    default
role    testrole
acl_profile       test_profile0
client_profile    n/a
guaranteed_endpoint_permission_override    true
subscription_manager                       false
username_prefix		slowBoring
bash-5.0# vault read solace-plugin/roles/testrole
Key     Value
---     -----
acl_profile       test_profile0
client_profile    n/a
role    testrole
ttl     600s
config_name    default
vpn     testvpn
username_prefix		slowBoring
guaranteed_endpoint_permission_override    true
subscription_manager                       false
bash-5.0# vault list solace-plugin/roles
Keys
----
testrole

```
Durations less than 1s are not supported.

### Dynamic credentials
```
bash-5.0# vault read solace-plugin/creds/testrole
Key                                        Value
---                                        -----
lease_id                                   solace-plugin/creds/test2role/uDHPFH9So40TQJumYTPvxBhc
lease_duration                             768h
lease_renewable                            true
acl_profile                                test_profile0
client_profile                             n/a
guaranteed_endpoint_permission_override    true
password                                   8a716d67-5dbf-4658-b5fa-2307f1821bd1
role                                       test2role
subscription_manager                       false
ttl                                        0s
username                                   c0cd2745-25ef-418c-99d3-3f5227a9276f
vpn                                        testvpn0

```
It is possible to add non-random prefix to the username. In case UsernamePrefix is set for the role, `prefix` overrides it.
```
bash-5.0# vault read solace-plugin/creds/test2role prefix=superfish
Key                                        Value
---                                        -----
lease_id                                   solace-plugin/creds/test2role/RFbvn4G85i6mVKfeAZs3BJWQ
lease_duration                             768h
lease_renewable                            true
acl_profile                                test_profile0
client_profile                             n/a
guaranteed_endpoint_permission_override    true
password                                   3d035893-e35b-47ca-8855-76ef3d9d4354
role                                       test2role
subscription_manager                       false
ttl                                        0s
username                                   superfish-463d-8ba1-3d6c65a82781
vpn                                        testvpn0
```
|Parameter|Description|Mandatory|
----------|-----------|-----------
|prefix|Will be added to the randomly generated username|No|

Revocation:
```
bash-5.0# vault lease revoke solace-plugin/creds/testrole/E85owV8zhstL2vrkkKhDVMn4
All revocation operations queued successfully!
```
On revocation user in Solace is dropped.

## Static credentials
```
bash-5.0# vault write solace-plugin/user/testuser role=test2role
Key                                        Value
---                                        -----
acl_profile                                test_profile0
client_profile                             n/a
guaranteed_endpoint_permission_override    true
password                                   c6392c90-d2be-4a93-b6c1-61c80d76861e
subscription_manager_enabled               false
username                                   testuser
vpn                                        testvpn0

bash-5.0# vault read solace-plugin/user/testuser role=test2role
Key                                        Value
---                                        -----
acl_profile                                test_profile0
client_profile                             default
enabled                                    true
guaranteed_endpoint_permission_override    true
subscription_manager_enabled               false
username                                   testuser
vpn                                        testvpn0

bash-5.0# vault delete solace-plugin/user/testuser role=test2role
Success! Data deleted (if it existed) at: solace-plugin/user/testuser
```

## How to generate SEMPv2 client API

Download go-swagger and
```bash
[pripii@priitp-roadkill solace-plugin]$ ~/swagger_linux_amd64 generate client -f http://localhost:8080/SEMP/v2/config/spec -t gen -c solaceapi
[pripii@priitp-roadkill solace-plugin]$ go mod tidy
```

Plugin source tree contains only a small subset of the SEMP2 API which is actually used. Rest is manually removed.

### Tests

```bash
cd plugin && go test -v
```

Tests use Vault test backend, but connect to the live Solace. Config parameters are in `backend_test.go`. 

In case of issues, setting DEBUG environment variable to something makes generated api to produce copious amount of debug info, including
requests and responses. For example:
```bash
[pripii@priitp-roadkill solace-plugin]$ DEBUG=nihao go test -run TestApiDeleteUser
DELETE /SEMP/v2/config/msgVpns/testvpn0/clientUsernames/client0 HTTP/1.1
Host: localhost:8080
User-Agent: Go-http-client/1.1
Accept: application/json
Authorization: Basic YWRtaW46YWRtaW4=
Content-Type: application/json
Accept-Encoding: gzip


HTTP/1.1 400 Bad Request
Transfer-Encoding: chunked
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With
Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS
Cache-Control: no-store
Connection: keep-alive
Content-Type: application/json
Date: Thu, 01 Oct 2020 09:14:02 GMT
Server: Solace_VMR/9.6.0.38
Strict-Transport-Security: max-age=31536000

173
{
    "meta":{
        "error":{
            "code":6,
            "description":"Could not find match for clientUsernames client0",
            "status":"NOT_FOUND"
        },
        "request":{
            "method":"DELETE",
            "uri":"http://localhost:8080/SEMP/v2/config/msgVpns/testvpn0/clientUsernames/client0"
        },
        "responseCode":400
    }
}
0


--- FAIL: TestApiDeleteUser (0.05s)
    solapi_test.go:87: [DELETE /msgVpns/{msgVpnName}/clientUsernames/{clientUsername}][400] deleteMsgVpnClientUsername default  &{Meta:0xc0005a94a0}
FAIL
exit status 1
FAIL    kindredgroup.com/solace-plugin   0.086s

```
