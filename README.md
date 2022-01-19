<a href="http://tarantool.org">
   <img src="https://avatars2.githubusercontent.com/u/2344919?v=2&s=250"
align="right">
</a>

# ACME-client for Tarantool 1.7.5+

## Table of contents
* [General information](#general-information)
* [Installation](#installation)
* [Preparing for work](#preparing-for-work)
* [An example of using the module](#an-example-of-using-the-module)

## General information
Link to [GitHub](https://github.com/a1div0/acme-client "GitHub").

The ACME protocol client is used to automatically obtain a security certificate for your site. Basically everyone uses [Let's Encrypt](https://letsencrypt.org/ "Let's Encrypt") to get a free certificate and auto-renewal. But there are other services, such as [Zero SSL](https://zerossl.com/ "Zero SSL"). It also supports the ACME protocol.

I relied on two articles from Habr ([this](https://habr.com/ru/company/ispsystem/blog/354420/"this") and [this](https://habr.com/ru/company/ispsystem/blog/413429/ "this")), as well as [RFC8555](https://datatracker.ietf.org/doc/html/rfc8555 "RFC8555"). But the information in them was not enough to implement their own version of the modulation. At least several times higher than several implementations of the module [at another level]. The tests were conducted on a live service, so there are no autotests yet. You can write and init pull request.

The module is written under Linux. Only the second version of the protocol is considered.

## Installation
You can:
* Clone repository:
``` shell
git clone https://github.com/a1div0/acme-client.git
```

## Preparing for work
### CSR
You must first submit a Certificate Signing Request - [CSR](https://en.wikipedia.org/wiki/Certificate_signing_request "CSR"). This file (let's call it `csr.pem`) contains information about the future domain and organization. Namely, there are fields:
1. Domain name (CN) - for which the certificate is issued;
2. Organization (O) - the full name of the organization that owns the site;
3. Department (OU) - groups of organizations involved in the issuance of a certificate;
4. Country (C) - [code](https://ru.wikipedia.org/wiki/ISO_3166-1_alpha-2 "ISO 3166-1 alpha-2") of two characters corresponding to the organization's country ([list]( https://ru.wikipedia.org/wiki/ISO_3166-2 "ISO 3166-2"));
5. State/Province (ST) and city (L) - the location of the organization;
6. e-mail (EMAIL) - mail for communication with the contact.

You can generate such a file using online generators, for example [here] (https://csrgenerator.com/ "CSR Generator") and [here] (https://www.reg.ru/ssl-certificate/generate_key_and_csr "Creating certificate request"). You can use OpenSSL. To do this, enter a command like:
```
openssl genrsa -out private.key 4096
openssl req -new -key private.key -out domain_name.csr -sha256
```
Next, you need to enter the above information and request. You should get a text file like this:
```
-----START CERTIFICATE REQUEST-----
MIICyDCCAbACAQAwgYIxCzAJBgNVBAYTALJVMSQwIgYDVQQIDBvQkNC70YLQsNC5
...
Mf5rbR8Ok/PfHohVHsOp85mAyTInt7a5H4PHVHb7U8j5aPhc4HarH+LcJhM=
-----END OF CERTIFICATE REQUEST-----

-----START PRIVATE KEY-----
MIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgeEAAoIBAQCttTORMQRaZYq2
...
QARm4Qu60qmM30MrhtCYOBk=
-----END PRIVATE KEY-----
```

There are plans to automate the process of creating a CSR, since it is practically possible to distribute a certificate with it, but it is better to create a new one each time.

### Add and configure a module
The module returns an object by procedures:

#### Init
```
init(settings)
```
This production procedure allows you to create structures and transfers. Contains the `settings` parameter, which is a table with fields:
* `dnsName` - required field, domain name with a certificate;
* `certPath` - required field, full path to the folder with certificates;
* `certName` - optional, default = `cert.pem`, this is the name of the file, the certificate will be created with the animals;
* `csrName` - required field, the name of the certificate signing request file created earlier and placed in the `certPath` folder;
* `challengeType` - optional, default = `http-01`, this setting indicates what type of verification that you own the domain will be in the Republic. There are two options available: `http01` and `dns01`. The first type of verification confirms ownership, the impact of a GET request on a specific site address. The second type of check makes a DNS query. The second type of verification is required if a certificate for a domain name is encountered with all subdomains at once: `*.domain.name` (wildcard certificates). More details can be found below in the article and [here](https://letsencrypt.org/en/docs/challenge-types/ "here").
* `acmeDirectoryUrl` - optional, default = "https://acme-v02.api.letsencrypt.org/directory", this is the path to the entry point of the ACME-server.

#### onSetupChallengeHttp01
```
onSetupChallengeDns01(key, value)
```
This procedure must be overridden if the `dns01` check is used. The procedure will be called when a DNS record of type `TXT` needs to be set. At the time of the call, the module will pass the key name `key` and its value `value`, which must be recorded in DNS.
The procedure is called twice - once to set the entry, the second time to cancel the setting (nil will be passed in the `value` parameter).
An example implementation of this type of validation is beyond the scope of this article.

#### getCert
```
getCert()
```
This procedure starts the process of automatically obtaining a certificate. It contains no parameters.

## An example of using the module
The example uses an external module - [http.server](https://github.com/tarantool/http "http.server").
``` lua
    local server = require("http.server").new("123.45.67.89", 80) -- 123.45.67.89 - server's internal ip, 80 - listening port number
    local acmeClient = require("acme-client")
    acmeClient:init(settings)

    acmeClient.onSetupChallengeHttp01 = function (url, body)
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

    acmeClient:getCert()
```