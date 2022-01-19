#!/usr/bin/env tarantool

package.path = "../acme-client/?.lua;"..package.path

require('ide-debug')
local acmeClient = require("acme-client")
local tap = require('tap')

local test = tap.test('acme-client tests')
test:plan(1)

test:test('acme-client', function(test)
    test:plan(1)
    --test:is(kit.test(1), 11, "Lua function in acme-client.lua")

    local settings = {
        dnsName = "a",
        certPath = "",
        csrName = "csr.pem"
    }
    local res = {}

    acmeClient:init(settings)
    acmeClient.onSetupChallengeDns01 = function (key, value)
        return {key, value}
    end
    res = acmeClient:setupChallengeDns01("123")
    test:ok(res[1] == "_acme-challenge.a", "Check setupChallengeDns01 - dns name = a")
    test:ok(res[2] == "123", "Check setupChallengeDns01 - check value")

    acmeClient.dnsName = "*.test.ru"
    res = acmeClient:setupChallengeDns01("123")
    test:ok(res[1] == "_acme-challenge.test.ru", "Check setupChallengeDns01 - dns name = *.test.ru")
    test:ok(res[2] == "123", "Check setupChallengeDns01 - check value")
end)

os.exit(test:check() == true and 0 or -1)
