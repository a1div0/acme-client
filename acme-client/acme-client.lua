-- acme-client

local acmeClient = {}

local function execute(command)
    local popen = require("popen")
    local prog = popen.shell(command, "r")
    prog:wait()
    local outputStr = prog:read()
    prog:close()
    return outputStr
end

local function base64url(self, data)
    local opt = {
        nowrap = true,
        urlsafe = true
    }
    return self.digest.base64_encode(data, opt)
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



local function loadCsr(self)
    local fileName = self.certPath .. self.csrName
    local file = io.open(fileName, "r")
    if not file then
        error("Не удалось открыть файл "..fileName)
    end
    local pemData = file:read "*a"
    file:close()

    local csrB64 = getSection(pemData, "-----BEGIN CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST-----")
    if csrB64 == nil then
        error("Секция с запросом (Certificate Signing Request) не обнаружена!")
    end
    self.csr = self.digest.base64_decode(csrB64)
end

local function createRsaPrivateKey(self)
    local command = string.format("openssl genrsa -out %s 2048", self.rsaPrivateKeyFileName)
    execute(command)

    local file = io.open(self.rsaPrivateKeyFileName, "r")
    if not file then
        error("RSA private key - не был сформирован!")
    end
    local data = file:read "*a" -- *a or *all reads the whole file
    file:close()

    local rsaPrivateKey = getSection(data, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----")
    if rsaPrivateKey == nil then
        rsaPrivateKey = getSection(data, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----")
        if rsaPrivateKey == nil then
            error("Секция с приватным ключом не обнаружена!")
        end
    end

    self.rsaPrivateKey = self.digest.base64_decode(rsaPrivateKey)
end

local function getRsaPrivateKeyParam1(self)
    local command = string.format("openssl rsa -text -noout < %s", self.rsaPrivateKeyFileName)
    local outputStr = execute(command)
    local findPhrase = "publicExponent: "
    local textLines = self.string.split(outputStr, "\n")
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

local function getRsaPrivateKeyParam2(self)
    local command = string.format("openssl rsa -noout -modulus < %s", self.rsaPrivateKeyFileName)
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
    local modulusBin = self.string.fromhex(self.modulus)

    self.jwk = string.format(
        [[{"e":"%s","kty":"RSA","n":"%s"}]]
        , base64url(self, publicExponentBin) -- публичная экспонента ключа в виде HexToBase64UrlEnodedByte
        , base64url(self, modulusBin) -- modulus ключа в виде HexToBase64UrlEnodedByte
    )
end

local function requestSettings(self)
    local clientObj = self.httpClient.new()
    local resp = clientObj:request("GET", self.acmeDirectoryUrl)
    if (resp.status < 200) or (resp.status >= 300) then
        error("Неправильный ответ 2")
    end
    self.directory = self.json.decode(resp.body)

    resp = clientObj:request("HEAD", self.directory.newNonce)
    if (resp.status < 200) or (resp.status >= 300) then
        error("Неправильный ответ 2")
    end

    self.replayNonce = resp.headers["replay-nonce"]
    if self.replayNonce == nil then
        error("Не удалось получить Replay-Nonce")
    end
end

local function signature(self, data)
    local command = string.format("printf '%s' | openssl dgst -binary -sha256 -sign %s"
    , data
    , self.rsaPrivateKeyFileName
    )
    local signatureBin = execute(command)
    if signatureBin == nil or signatureBin == "" then
        error("Что-то пошло не так - не удалось получить сигнатуру")
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
    local protectedB64 = base64url(self, protected)

    local payload = self.json.encode(payloadStruct)
    local payloadB64 = base64url(self, payload)

    local signatureBin = signature(self, protectedB64.."."..payloadB64)
    local signatureB64 = base64url(self, signatureBin)

    local bodyStruct = {
        protected = protectedB64,
        payload = payloadB64,
        signature = signatureB64
    }
    local body = self.json.encode(bodyStruct)

    local clientObj = self.httpClient.new()
    local headers = {
        ["Content-Type"] = "application/jose+json"
    }
    local resp = clientObj:request("POST", url, body, {headers = headers})

    if (resp.status < 200) or (resp.status >= 300) then
        local errText = string.format("Ошибка! Код ответа = %d. Запрос на адрес: %s\n", resp.status, url)..resp.body
        error(errText)
    end

    self.replayNonce = resp.headers["replay-nonce"]

    return resp
end

local function getInstructions(self)
    local clientObj = self.httpClient.new()
    local resp = clientObj:request("GET", self.orderData.authorizations[1])
    if (resp.status < 200) or (resp.status >= 300) then
        error("Неправильный ответ 2")
    end
    self.instructions = self.json.decode(resp.body)
end

local function getChallenge(self)
    for _, challengeData in ipairs(self.instructions.challenges) do
        if challengeData.type == self.challengeType then
            return challengeData
        end
    end

    return nil
end

local function httpGet(self, url, decode)
    local clientObj = self.httpClient.new()
    local resp = clientObj:request("GET", url)
    if (resp.status < 200) or (resp.status >= 300) then
        local errText = string.format("Ошибка! Код ответа = %d. Запрос на адрес: %s\n", resp.status, resp.body)..resp.body
        error(errText)
    end
    local result = nil
    if decode == false then
        result = resp.body
    else
        result = self.json.decode(resp.body)
    end
    return result
end

local function waitReady(self)
    local timeoutSec = 10
    local sleepSec = 0.25
    local maxIterate = timeoutSec / sleepSec
    local orderReady = false

    local fiber = require("fiber")

    for _ = 1, maxIterate do
        fiber.sleep(sleepSec)
        local orderResult = httpGet(self, self.orderUrl)
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

local function loadAndSaveCert(self)

    local payload = {
        csr = base64url(self, self.csr)
    }

    local resp = acmeRequest(self, self.orderData.finalize, payload)
    local respData = self.json.decode(resp.body)
    if (respData.status ~= "valid") then
        error("Failed to finalize order at " .. self.orderData.finalize .. "\n" .. respData.body)
    end

    local certBin = httpGet(self, respData.certificate, false)

    local fileName = self.certPath .. self.certName
    local file = io.open (fileName, "w+")
    file:write(certBin)
    file:close()

end

local function setupChallengeHttp01(self, token, keyAuthorization)
    local url = "/.well-known/acme-challenge/" .. token
    self.onSetupChallengeHttp01(url, keyAuthorization)
end

local function setupChallengeDns01(self, keyAuthorization)
    local key = "_acme-challenge.<YOUR_DOMAIN>"
    self.onSetupChallengeDns01(key, keyAuthorization)
end

local function setupChallenge(self, token, keyAuthorization)
    if self.challengeType == "http-01" then
        setupChallengeHttp01(self, token, keyAuthorization)
    elseif self.challengeType == "dns-01" then
        setupChallengeDns01(self, keyAuthorization)
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
    self.orderData = self.json.decode(resp.body)
    self.orderUrl = resp.headers["location"]
end

local function selfCheck(self)
    if self.challengeType == "http-01" then
        if self.onSetupChallengeHttp01 == nil then
            error("Необходимо задать обработчик onSetupChallengeHttp01!")
        end
    elseif self.challengeType == "dns-01" then
        if self.onSetupChallengeDns01 == nil then
            error("Необходимо задать обработчик onSetupChallengeDns01!")
        end
    else
        error("Тип проверки "..self.challengeType.." не поддерживается!")
    end
end

function acmeClient:init(settings)
    self.dnsName = settings.dnsName
    self.certPath = settings.certPath
    self.certName = settings.certName or "cert.pem"
    self.csrName = settings.csrName
    self.challengeType = settings.challengeType or "http-01"
    self.acmeDirectoryUrl = settings.acmeDirectoryUrl or "https://acme-v02.api.letsencrypt.org/directory"

    self.rsaPrivateKeyFileName = settings.certPath .. "rsa-temp.pem"
    self.json = require("json")
    self.httpClient = require("http.client")
    self.digest = require("digest")
    self.string = require("string")
end

function acmeClient:getCert()

    selfCheck(self)
    loadCsr(self)
    createRsaPrivateKey(self)
    getRsaPrivateKeyParam1(self)
    getRsaPrivateKeyParam2(self)
    buildJwk(self)
    requestSettings(self)
    newAccount(self)
    newOrder(self)
    getInstructions(self)

    local challengeData = getChallenge(self)
    local jwkHashBin = self.digest.sha256(self.jwk)
    local keyAuthorization = challengeData.token .. "." .. base64url(self, jwkHashBin)
    setupChallenge(self, challengeData.token, keyAuthorization)

    local payload = {
        resource = "challenges",
        keyAuthorization = keyAuthorization
    }
    acmeRequest(self, challengeData.url, payload)
    waitReady(self)
    loadAndSaveCert(self)

    setupChallenge(self, challengeData.token, nil)
end

acmeClient.onSetupChallengeHttp01 = nil
acmeClient.onSetupChallengeDns01 = nil

return acmeClient