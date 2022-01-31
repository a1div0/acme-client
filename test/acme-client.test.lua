#!/usr/bin/env tarantool

--package.path = "../acme-client/?.lua;"..package.path

require('test.ide-debug')
local acmeClient = require("acme-client")
local tap = require('tap')
local test = tap.test('acme-client tests')

local function main_acme_client_test()
    local settings = {
        dnsName = "myname.dns",
        certPath = "/home/alex/projects/acme-client/test/cert/",
    }
    local function myChallengeSetup(key, value)
        return {key, value}
    end
    local acme = acmeClient.new(settings, myChallengeSetup)
    acme:getCert() --https://www.switch.ch/pki/manage/request/csr-openssl/

    local validTo = acme:validTo()
    print(os.date("%Y.%m.%d %H:%M:%S", validTo))
end

main_acme_client_test()

--[[
test:plan(1)

test:test('acme-client', function(test)
    test:plan(1)
    --test:is(kit.test(1), 11, "Lua function in init.lua")
    --main_acme_client_test()
end)

os.exit(test:check() == true and 0 or -1)
]]