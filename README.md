<a href="http://tarantool.org">
   <img src="https://avatars2.githubusercontent.com/u/2344919?v=2&s=250"
align="right">
</a>

# ACME-client for Tarantool

## Table of contents
* [General information](#general-information)
* [Installation](#installation)
* [API](#api)
* [An example of using the module](#an-example-of-using-the-module)
* [Possible problems](#possible-problems)

## General information
Link to [GitHub](https://github.com/a1div0/acme-client "GitHub"). More details
about the operation of the algorithm and the module can be found
[here](https://1div0.ru/about-acme-client/).

The ACME protocol client is used to automatically obtain a security certificate
for your site. Basically everyone uses [Let's Encrypt](https://letsencrypt.org/
"Let's Encrypt") to get a free certificate and auto-renewal. But there are other
services, such as [Zero SSL](https://zerossl.com/ "Zero SSL"). It also supports
the ACME protocol.

I relied on two articles from Habr ([this](https://habr.com/ru/company/ispsystem/blog/354420/"this")
and [this](https://habr.com/ru/company/ispsystem/blog/413429/ "this")), as well
as [RFC8555](https://datatracker.ietf.org/doc/html/rfc8555 "RFC8555"). But the
information in them was not enough to implement their own version of the
module. Implementations of the module in [other languages](https://letsencrypt.org/ru/docs/client-options/)
were analyzed. The tests were conducted on a live service, so there are no
autotests yet. You can write and init pull request.

The module is written under Linux. Used ACME version 2 (version 1 - not
realized).

## Installation
You can:
* clone the repository:
``` shell
git clone https://github.com/a1div0/acme-client.git
```
* install the `acme-client` module using `tarantoolctl`:
```shell
tarantoolctl rocks install acme-client
```

## API
* `local acmeLib = require('acme-client')` - acquire a library handle
* `local acmeClient = acmeLib.new(options, proc)` - create new acme-object
* `local time = acmeLib.certValidTo(certName)` - returns the expiration date of
the certificate
* `acmeClient:getCert()` - the procedure starts the mechanism for
automatically obtaining a SSL-certificate
* `acmeClient:validTo()` - returns the expiration date of the certificate

### new
```
new(options, yourChallengeSetupProc)
```
This procedure create a new acme-client object with the specified parameters.
The `options` parameter, which is a table with fields:
* `dnsName` - required field, domain name with a certificate
* `certPath` - required field, full path to the folder with certificates
* `certName` - optional, default = `cert.pem`, this is the name of the file,
with which the certificate will be created
* `tempRsaPrivateKeyName` - optional, default = `privacc.pem`, is name temporary
file with private rsa key
* `tempCsrConfName` - optional, default = `csr.cnf`, is name temporary file
with configuration parameters for CSR
* `tempCsrName` - optional, default = `csr.pem`, is name temporary file with CSR
* `challengeType` - optional, default = `http-01`, this setting indicates what
type of verification that you own the domain will be used. There are two options
available: `http01` and `dns01`. The first type of verification confirms
ownership, the impact of a GET request on a specific site address. The second
type of check makes a DNS query. The second type of verification is required if
a certificate for a domain name is encountered with all subdomains at once:
`*.domain.name` (wildcard certificates). More details can be found below in the
article and [here](https://letsencrypt.org/en/docs/challenge-types/ "here").
* `acmeDirectoryUrl` - optional, default =
`https://acme-v02.api.letsencrypt.org/directory`, this is the path to the entry
point of the ACME-server.
* `organization` - optional, if the level of the certificate allows, you can add
the name of your organization to it
* `organizationUnit` - optional, if the level of the certificate allows, you can
add the name of your organization unit to it
* `country` - optional, if the level of the certificate allows, you can add
  the name of your country to it. It must be a [two letter code](https://ru.wikipedia.org/wiki/ISO_3166-2).
* `state` - optional, if the level of the certificate allows, you can add
  the name of your state or region to it
* `city` - optional, if the level of the certificate allows, you can add
  the name of your city to it
* `email` - optional, if the level of the certificate allows, you can add email
  to contact you

The level of the certificate is determined by the service used.

The second parameter is `proc` - this is your procedure to make sure your server
does the ACME check. Implementation depends on the type of validation:

If `http-01`
```lua
function yourProc(url, body)
    -- your code --
end
```
The procedure will be called when the server response needs to be set. The
server must listen on port `80` if we receive an SSL certificate for the first
time. Or `443` if you have a valid SSL certificate. At the time of the call, the
module will pass as parameters:
* `url` - the address to which the response should be set. It will be a line
like `/.well-known/acme-challenge/<token>`
* `body` - the text to be returned when a GET-request arrives at the specified
address. The procedure is called twice - once to set the response, the second
time to cancel the installation. If body contains text, response code should
be = `200`. If body == nil, then response code should be `404`.

If `dns-01`
``` lua
function yourProc(key, value)
    -- your code --
end
```
The procedure will be called when a DNS record of type `TXT` needs to be set. At
the time of the call, the module will pass the key name `key` and its value
`value`, which must be recorded in DNS. The procedure is called twice - once to
set the entry, the second time to cancel the setting (nil will be passed in the
`value` parameter).

An example implementation of this type of validation is beyond the scope of this
article.

### acmeClientObject:getCert()
This procedure starts the process of automatically obtaining a certificate.

### acmeClientObject:validTo()
Gets the expiration date of the certificate specified since `certName` in the
current time zone.

## An example of using the module
The example uses an external module - [http.server](https://github.com/tarantool/http "http.server").
``` lua
    local acmeSettings = {
        dnsName = 'mysite.com'
        ,certPath = '/home/my/projects/project123/cert/'
        ,certName = 'certificate.pem'
        ,challengeType = 'http-01'
    }
    local function myChallengeSetup(url, body)
        local proc = nil
        if body ~= nil then
            proc = function (request)
                return request:render{status = 200, text = body}
            end
        else
            proc = function (request)
                return request:render{status = 404}
            end
        end
        server:route({ path = url }, proc)
    end
    
    local acmeClient = require("acme-client").new(settings, myChallengeSetup)
    local server = require("http.server").new(nil, 80)
    
    acmeClient:getCert()
    
    local validTo = acmeClient:validTo()
    print(os.date("%Y.%m.%d %H:%M:%S", validTo))
```

## Possible problems
If there is a problem, pay attention to the [limits](https://letsencrypt.org/ru/docs/rate-limits/ "limits")
of the service. For example, Let's Encrypt issues no more than 5 free
certificates per domain per week. There are limits on the number of
requests - during debugging on a live service, they are easy to exceed.