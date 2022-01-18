#!/usr/bin/env tarantool

local kit = require('acme-client')
local tap = require('tap')

local test = tap.test('acme-client tests')
test:plan(1)

test:test('acme-client', function(test)
    test:plan(1)
    test:is(kit.test(1), 11, "Lua function in acme-client.lua")
end)

os.exit(test:check() == true and 0 or -1)
