#!/usr/bin/env tarantool

package.path = "../acme-client/?.lua;"..package.path

--require('ide-debug')
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

    local function myChallengeSetup(key, value)
        return {key, value}
    end

end)

os.exit(test:check() == true and 0 or -1)
