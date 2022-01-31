-- acme-client, v2.0

local json = require("json")
local fio = require("fio")
local httpClient = require("http.client")
local digest = require("digest")
local string = require("string")
local popen = require("popen")

local function errorf(fmt, ...)
    error(string.format(fmt, ...))
end

local function execute(command)
    local prog = popen.shell(command, "r")
    prog:wait()
    local outputStr = prog:read()
    prog:close()
    return outputStr
end

local function base64url(data)
    local opt = {
        nowrap = true,
        urlsafe = true
    }
    return digest.base64_encode(data, opt)
end

local function numberStringToBin(numberStr)
    local e = tonumber(numberStr)
    local res = ""
    while e > 0 do
        local byte = e % 256
        res = res .. string.char(byte)
        e = math.floor(e / 256)
    end
    return res
end

local function getSection(text, prefix, postfix)
    local str = string.gsub(text, "\n", "")
    local posPrefix = string.find(str, prefix, 1, true)
    local posPostfix = string.find(str, postfix, posPrefix, true)
    if posPrefix == nil or posPostfix == nil then
        return nil
    end

    return string.sub(str, posPrefix + string.len(prefix), posPostfix - 1)
end

local function httpGet(url, decode)
    local clientObj = httpClient.new()
    local resp = clientObj:request("GET", url)
    if (resp.status < 200) or (resp.status >= 300) then
        local errText = string.format("Error! Response code = %d. Url request: %s\n", resp.status, resp.body)..resp.body
        error(errText)
    end
    local result = nil
    if decode == false then
        result = resp.body
    else
        result = json.decode(resp.body)
    end
    return result
end

local cfgFormat = [[
FQDN = %s
ORGNAME = "%s"
ALTNAMES = DNS:$FQDN
[req]
default_bits = 4096
default_md = sha256
prompt = no
encrypt_key = no
distinguished_name = dn
req_extensions = req_ext
[req_ext]
subjectAltName = $ALTNAMES
[dn]
CN = $FQDN
O = $ORGNAME
OU = "%s"
C = "%s"
ST = "%s"
L = "%s"
]]

local function csrConfCreate(self)
    local cnf = string.format(cfgFormat,
            self.dnsName,
            self.organization,
            self.organizationUnit,
            self.country,
            self.state,
            self.city
    )
    if self.email ~= nil then
        cnf = cnf..string.format([[emailAddress = "%s"]], self.email)
    end

    local file = fio.open(self.csrConfName, {"O_WRONLY", "O_CREAT"})
    if not file then
        error("Failed to write csr-configuration file: "..self.csrConfName)
    end
    file:write(cnf)
    file:close()
    fio.chmod(self.csrConfName, tonumber('660', 8))
end

local function csrCreate(self)
    local command = string.format("openssl req -new -config '%s' -out '%s'", self.csrConfName, self.csrName)
    self.rsaPrivateKeySection = execute(command)

    os.remove(self.csrConfName)
end

local function csrLoad(self)
    local file = fio.open(self.csrName, {"O_RDONLY"})
    if not file then
        error("Failed to open file "..self.csrName)
    end
    local pemData = file:read()
    file:close()

    local csrB64 = getSection(pemData, "-----BEGIN CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST-----")
    if csrB64 == nil then
        error("Section 'Certificate Signing Request' not found!")
    end
    self.csr = digest.base64_decode(csrB64)

    os.remove(self.csrName)
end

local function createPrivateKey(self)
    local command = string.format("openssl genrsa -out '%s' 2048", self.privateAccName)
    execute(command)
end

local function getPublicParam1(self)
    local command = string.format("openssl rsa -text -noout < '%s'", self.privateAccName)
    local outputStr = execute(command)
    local findPhrase = "publicExponent: "
    local textLines = string.split(outputStr, "\n")
    for _, lineStr in ipairs(textLines) do
        local pos = string.find(lineStr, findPhrase, 1, true)
        if pos ~= nil then
            local publicExponentStr = string.sub(lineStr, pos + string.len(findPhrase))
            pos = string.find(publicExponentStr, " ")
            if pos ~= nil then
                publicExponentStr = string.sub(publicExponentStr, 1, pos - 1)
            end
            self.publicExponent = publicExponentStr
            break
        end
    end

    if self.publicExponent == nil then
        error("Error: failed to extract publicExponent!")
    end
end

local function getPublicParam2(self)
    local command = string.format("openssl rsa -noout -modulus < '%s'", self.privateAccName)
    local outputStr = execute(command)
    local pos = string.find(outputStr, "=")
    if pos ~= nil then
        self.modulus = string.sub(outputStr, pos + 1, -2)
    else
        self.modulus = outputStr
    end
end

local function buildJwk(self)
    local publicExponentBin = numberStringToBin(self.publicExponent)
    local modulusBin = string.fromhex(self.modulus)

    self.jwk = string.format(
            [[{"e":"%s","kty":"RSA","n":"%s"}]]
    , base64url(publicExponentBin) -- публичная экспонента ключа в виде HexToBase64UrlEnodedByte
    , base64url(modulusBin) -- modulus ключа в виде HexToBase64UrlEnodedByte
    )
end

local function requestSettings(self)
    local clientObj = httpClient.new()
    local resp = clientObj:request("GET", self.acmeDirectoryUrl)
    if (resp.status < 200) or (resp.status >= 300) then
        error("Settings not received")
    end
    self.directory = json.decode(resp.body)

    resp = clientObj:request("HEAD", self.directory.newNonce)
    if (resp.status < 200) or (resp.status >= 300) then
        error("Nonce not received")
    end

    self.replayNonce = resp.headers["replay-nonce"]
    if self.replayNonce == nil then
        error("Replay-Nonce missing from response")
    end
end

local function signature(self, data)
    -- openssl first gets the sha-256 hash of the message, then signs it with
    -- the private key
    -- In future see: https://github.com/spacewander/lua-resty-rsa
    local command = string.format(
            "printf '%s' | openssl dgst -binary -sha256 -sign '%s'"
    , data
    , self.privateAccName
    )
    local signatureBin = execute(command)
    if signatureBin == nil or signatureBin == "" then
        error("Something went wrong - could not get the signature")
    end

    return signatureBin
end

local function acmeRequest(self, url, payloadStruct)

    local protected = ""

    if self.kid == nil then
        protected = string.format([[{"alg":"RS256","jwk":%s,"url":"%s","nonce":"%s"}]]
        , self.jwk
        , url
        , self.replayNonce
        )
    else
        protected = string.format([[{"alg":"RS256","kid":"%s","url":"%s","nonce":"%s"}]]
        , self.kid
        , url
        , self.replayNonce
        )
    end
    local protectedB64 = base64url(protected)

    local payload = json.encode(payloadStruct)
    local payloadB64 = base64url(payload)

    local signatureBin = signature(self, protectedB64.."."..payloadB64)
    local signatureB64 = base64url(signatureBin)

    local bodyStruct = {
        protected = protectedB64,
        payload = payloadB64,
        signature = signatureB64
    }
    local body = json.encode(bodyStruct)

    local clientObj = httpClient.new()
    local headers = {
        ["Content-Type"] = "application/jose+json"
    }
    local resp = clientObj:request("POST", url, body, {headers = headers})

    if (resp.status < 200) or (resp.status >= 300) then
        local errText = string.format("Error! Response code = %d. Url request: %s\n", resp.status, url)..resp.body
        error(errText)
    end

    self.replayNonce = resp.headers["replay-nonce"]

    return resp
end

local function getInstructions(self)
    local clientObj = httpClient.new()
    local resp = clientObj:request("GET", self.orderData.authorizations[1])
    if (resp.status < 200) or (resp.status >= 300) then
        error("Failed to get instructions")
    end
    self.instructions = json.decode(resp.body)
end

local function getChallenge(self)
    for _, challengeData in ipairs(self.instructions.challenges) do
        if challengeData.type == self.challengeType then
            return challengeData
        end
    end

    return nil
end

local function waitReady(self)
    local timeoutSec = 10
    local sleepSec = 0.25
    local maxIterate = timeoutSec / sleepSec
    local orderReady = false

    local fiber = require("fiber")

    for _ = 1, maxIterate do
        fiber.sleep(sleepSec)
        local orderResult = httpGet(self.orderUrl)
        if orderResult.status == "ready" then
            orderReady = true
            break
        end
        if orderResult.status == "invalid" then
            break
        end
    end

    if orderReady ~= true then
        error("Order is not ready after retries. Please check if web server is responding correctly.")
    end
end

local function setupChallengeHttp01(self, token, keyAuthorization)
    local url = "/.well-known/acme-challenge/" .. token
    return self.onChallengeSetup(url, keyAuthorization)
end

local function setupChallengeDns01(self, keyAuthorization)
    local wildcard = self.dnsName:sub(1, 2) == "*."
    local dnsName = ""
    if wildcard then
        dnsName = self.dnsName:sub(3)
    else
        dnsName = self.dnsName
    end
    local key = "_acme-challenge."..dnsName
    return self.onChallengeSetup(key, keyAuthorization)
end

local function setupChallenge(self, token, keyAuthorization)
    if self.challengeType == "http-01" then
        setupChallengeHttp01(self, token, keyAuthorization)
    elseif self.challengeType == "dns-01" then
        setupChallengeDns01(self, keyAuthorization)
    else
        error("Challenge type "..self.challengeType.." not support!")
    end
end

local function newAccount(self)
    local payload = {termsOfServiceAgreed = true}
    local resp = acmeRequest(self, self.directory.newAccount, payload)
    self.kid = resp.headers["location"]
end

local function newOrder(self)
    local payload = {
        identifiers = {
            [1] = {
                type = "dns",
                value = self.dnsName
            }
        }
    }
    local resp = acmeRequest(self, self.directory.newOrder, payload)
    self.orderData = json.decode(resp.body)
    self.orderUrl = resp.headers["location"]
end

local function loadAndSaveCert(self)

    local payload = {
        csr = base64url(self.csr)
    }

    local resp = acmeRequest(self, self.orderData.finalize, payload)
    local respData = json.decode(resp.body)
    if (respData.status ~= "valid") then
        error("Failed to finalize order at " .. self.orderData.finalize .. "\n" .. respData.body)
    end

    local certBin = httpGet(respData.certificate, false)
    if certBin == nil or certBin == "" then
        error("Certificate data not received")
    end

    certBin = certBin.."\n"..self.rsaPrivateKeySection

    local file = fio.open(self.certName, {"O_WRONLY", "O_CREAT"})
    if not file then
        error("Failed to write certificate file")
    end
    file:write(certBin)
    file:close()

    fio.chmod(self.certName, tonumber('660', 8))
end

local function getCert(self)

    if self == nil then
        error("Must be call used `:getCert()`")
    end

    csrConfCreate(self)
    csrCreate(self)
    csrLoad(self)
    createPrivateKey(self) -- certificate public key must be different than account key
    getPublicParam1(self)
    getPublicParam2(self)
    buildJwk(self)
    requestSettings(self)
    newAccount(self)
    newOrder(self)
    getInstructions(self)

    local challengeData = getChallenge(self)
    local jwkHashBin = digest.sha256(self.jwk)
    local keyAuthorization = challengeData.token .. "." .. base64url(jwkHashBin)
    setupChallenge(self, challengeData.token, keyAuthorization)

    local payload = {
        resource = "challenges",
        keyAuthorization = keyAuthorization
    }
    acmeRequest(self, challengeData.url, payload)
    waitReady(self)
    loadAndSaveCert(self)

    setupChallenge(self, challengeData.token, nil)

    os.remove(self.privateAccName)
end

local function certValidTo(certName)
    local command = string.format("openssl x509 -enddate -noout -in '%s' | cut -d= -f 2", certName)
    local outputStr = execute(command)

    command = "date --date='aaa' +'%F %T'"
    command = command:gsub("aaa", outputStr)
    local formatedDate = execute(command)

    local year, month, day, hour, min, sec = formatedDate:match("(%d+)-(%d+)-(%d+) (%d+):(%d+):(%d+)")
    local datetime = {
        year = year,
        month = month,
        day = day,
        hour = hour,
        min = min,
        sec = sec,
    }
    local timezone = os.time() - os.time(os.date("!*t"))
    local result = os.time(datetime) + timezone

    return result
end

local function validTo(self)
    return certValidTo(self.certName)
end

local function checkNotEmpty(struct, fieldName)
    if struct[fieldName] == nil or struct[fieldName] == "" then
        errorf("Error: must specify %s!", fieldName)
    end
end

local exports = {
    certValidTo = certValidTo,
    new = function(options, yourChallengeSetupProc)
        if options == nil then
            options = {}
        end
        if type(options) ~= "table" then
            errorf("options must be table not '%s'", type(options))
        end
        if yourChallengeSetupProc == nil then
            error("You need to set a handler 'yourChallengeSetupProc'!")
        end

        local default = {
            certName = "cert.pem",
            --privateKeyName = "private.pem",
            privateAccName = "privacc.pem",
            csrConfName = "csr.cnf",
            csrName = "csr.pem",
            orgInfo = "Not specified",
            challengeType = "http-01",
            acmeDirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory",
        }

        checkNotEmpty(options, "dnsName")
        checkNotEmpty(options, "certPath")

        local self = {
            dnsName = options.dnsName,
            certPath = options.certPath,
            certName = options.certName or default.certName,
            privateAccName = options.tempRsaPrivateKeyName or default.privateAccName,
            csrName = options.tempCsrName or default.csrName,
            csrConfName = options.tempCsrConfName or default.csrConfName,
            challengeType = options.challengeType or default.challengeType,
            acmeDirectoryUrl = options.acmeDirectoryUrl or default.acmeDirectoryUrl,
            organization = options.organization or default.orgInfo,
            organizationUnit = options.organizationUnit or default.orgInfo,
            country = options.country or "EN",
            state = options.state or default.orgInfo,
            city = options.city or default.orgInfo,
            email = options.email,
            onChallengeSetup = yourChallengeSetupProc,

            -- methods
            getCert = getCert,
            validTo = validTo,
        }

        self.certName = self.certPath..self.certName
        self.privateAccName = self.certPath..self.privateAccName
        self.csrName = self.certPath..self.csrName
        self.csrConfName = self.certPath..self.csrConfName

        return self
    end
}

return exports