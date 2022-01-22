-- acme-client

local json = require("json")
local fio = require("fio")
local httpClient = require("http.client")
local digest = require("digest")
local string = require("string")
local popen = require("popen")

local acmeClient = {}

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

function acmeClient:loadCsr()
    local fileName = self.certPath .. self.csrName
    local file = fio.open(fileName, {"O_RDONLY"})
    if not file then
        error("Failed to open file "..fileName)
    end
    local pemData = file:read()
    file:close()

    local csrB64 = getSection(pemData, "-----BEGIN CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST-----")
    if csrB64 == nil then
        error("Section 'Certificate Signing Request' not found!")
    end
    self.csr = digest.base64_decode(csrB64)
end

function acmeClient:createRsaPrivateKey()
    local command = string.format("openssl genrsa -out '%s' 2048", self.rsaPrivateKeyFileName)
    execute(command)

    local file = fio.open(self.rsaPrivateKeyFileName, {"O_RDONLY"})
    if not file then
        error("RSA private key - was not formed!")
    end
    local data = file:read()
    file:close()

    local rsaPrivateKey = getSection(data, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----")
    if rsaPrivateKey == nil then
        rsaPrivateKey = getSection(data, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----")
        if rsaPrivateKey == nil then
            error("Section with private key not found!")
        end
    end

    self.rsaPrivateKey = digest.base64_decode(rsaPrivateKey)
end

function acmeClient:getRsaPrivateKeyParam1()
    local command = string.format("openssl rsa -text -noout < '%s'", self.rsaPrivateKeyFileName)
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
end

function acmeClient:getRsaPrivateKeyParam2()
    local command = string.format("openssl rsa -noout -modulus < '%s'", self.rsaPrivateKeyFileName)
    local outputStr = execute(command)
    local pos = string.find(outputStr, "=")
    if pos ~= nil then
        self.modulus = string.sub(outputStr, pos + 1, -2)
    else
        self.modulus = outputStr
    end
end

function acmeClient:buildJwk()
    local publicExponentBin = numberStringToBin(self.publicExponent)
    local modulusBin = string.fromhex(self.modulus)

    self.jwk = string.format(
            [[{"e":"%s","kty":"RSA","n":"%s"}]]
    , base64url(publicExponentBin) -- публичная экспонента ключа в виде HexToBase64UrlEnodedByte
    , base64url(modulusBin) -- modulus ключа в виде HexToBase64UrlEnodedByte
    )
end

function acmeClient:requestSettings()
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

function acmeClient:signature(data)
    local command = string.format("printf '%s' | openssl dgst -binary -sha256 -sign '%s'"
    , data
    , self.rsaPrivateKeyFileName
    )
    local signatureBin = execute(command)
    if signatureBin == nil or signatureBin == "" then
        error("Something went wrong - could not get the signature")
    end

    return signatureBin
end

function acmeClient:acmeRequest(url, payloadStruct)

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

    local signatureBin = self:signature(protectedB64.."."..payloadB64)
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

function acmeClient:getInstructions()
    local clientObj = httpClient.new()
    local resp = clientObj:request("GET", self.orderData.authorizations[1])
    if (resp.status < 200) or (resp.status >= 300) then
        error("Failed to get instructions")
    end
    self.instructions = json.decode(resp.body)
end

function acmeClient:getChallenge()
    for _, challengeData in ipairs(self.instructions.challenges) do
        if challengeData.type == self.challengeType then
            return challengeData
        end
    end

    return nil
end

function acmeClient:httpGet(url, decode)
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

function acmeClient:waitReady()
    local timeoutSec = 10
    local sleepSec = 0.25
    local maxIterate = timeoutSec / sleepSec
    local orderReady = false

    local fiber = require("fiber")

    for _ = 1, maxIterate do
        fiber.sleep(sleepSec)
        local orderResult = self:httpGet(self.orderUrl)
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

function acmeClient:loadAndSaveCert()

    local payload = {
        csr = base64url(self.csr)
    }

    local resp = self:acmeRequest(self.orderData.finalize, payload)
    local respData = json.decode(resp.body)
    if (respData.status ~= "valid") then
        error("Failed to finalize order at " .. self.orderData.finalize .. "\n" .. respData.body)
    end

    local certBin = self:httpGet(respData.certificate, false)

    local fileName = self.certPath .. self.certName
    local file = fio.open (fileName, {"O_WRONLY", "O_CREAT"})
    if not file then
        error("Failed to write certificate file")
    end
    file:write(certBin)
    file:close()

end

function acmeClient:setupChallengeHttp01(token, keyAuthorization)
    local url = "/.well-known/acme-challenge/" .. token
    return self.onChallengeSetup(url, keyAuthorization)
end

function acmeClient:setupChallengeDns01(keyAuthorization)
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

function acmeClient:setupChallenge(token, keyAuthorization)
    if self.challengeType == "http-01" then
        self:setupChallengeHttp01(token, keyAuthorization)
    elseif self.challengeType == "dns-01" then
        self:setupChallengeDns01(keyAuthorization)
    else
        error("Challenge type "..self.challengeType.." not support!")
    end
end

function acmeClient:newAccount()
    local payload = {termsOfServiceAgreed = true}
    local resp = self:acmeRequest(self.directory.newAccount, payload)
    self.kid = resp.headers["location"]
end

function acmeClient:newOrder()
    local payload = {
        identifiers = {
            [1] = {
                type = "dns",
                value = self.dnsName
            }
        }
    }
    local resp = self:acmeRequest(self.directory.newOrder, payload)
    self.orderData = json.decode(resp.body)
    self.orderUrl = resp.headers["location"]
end

function acmeClient.getCert(settings, yourChallengeSetupProc)

    if yourChallengeSetupProc == nil then
        error("You need to set a handler 'yourChallengeSetupProc'!")
    end

    acmeClient.dnsName = settings.dnsName
    acmeClient.certPath = settings.certPath
    acmeClient.certName = settings.certName or "cert.pem"
    acmeClient.rsaPrivateKeyName = settings.rsaPrivateKeyName or "private.pem"
    acmeClient.csrName = settings.csrName
    acmeClient.challengeType = settings.challengeType or "http-01"
    acmeClient.acmeDirectoryUrl = settings.acmeDirectoryUrl or "https://acme-v02.api.letsencrypt.org/directory"
    acmeClient.onChallengeSetup = yourChallengeSetupProc

    acmeClient.rsaPrivateKeyFileName = settings.certPath..acmeClient.rsaPrivateKeyName

    acmeClient:loadCsr()
    acmeClient:createRsaPrivateKey()
    acmeClient:getRsaPrivateKeyParam1()
    acmeClient:getRsaPrivateKeyParam2()
    acmeClient:buildJwk()
    acmeClient:requestSettings()
    acmeClient:newAccount()
    acmeClient:newOrder()
    acmeClient:getInstructions()

    local challengeData = acmeClient:getChallenge()
    local jwkHashBin = digest.sha256(acmeClient.jwk)
    local keyAuthorization = challengeData.token .. "." .. base64url(jwkHashBin)
    acmeClient:setupChallenge(challengeData.token, keyAuthorization)

    local payload = {
        resource = "challenges",
        keyAuthorization = keyAuthorization
    }
    acmeClient:acmeRequest(challengeData.url, payload)
    acmeClient:waitReady()
    acmeClient:loadAndSaveCert()

    acmeClient:setupChallenge(challengeData.token, nil)
end

return acmeClient