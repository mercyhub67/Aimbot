--[[
    AntiDump.lua
    Basic anti-dump / anti-extraction utility for Roblox Lua exploit scripts.
    Compatible with Delta and similar mobile executors.

    NOTE: This provides obfuscation-adjacent protection only.
    No client-side script can be 100% dump-proof — determined users with
    a capable executor can still bypass hookfunction-based defenses.
]]

local AntiDump = {}

-- 1. Detect if the environment has been tampered with (e.g. sandboxed getfenv)
local function checkEnvironment()
    local success, result = pcall(function()
        return getfenv(2)
    end)
    if success and result and result ~= getfenv() then
        return false
    end
    return true
end

-- 2. Hook common dump-related functions to block extraction of this script
local protectedScript = getfenv(1).script

local function blockDump()
    local blacklist = {
        "getscriptbytecode",
        "getscripthash",
        "decompile",
        "dumpstring",
        "getscriptclosure",
        "getsenv",
    }
    for _, fnName in ipairs(blacklist) do
        local fn = getfenv()[fnName]
        if fn then
            pcall(function()
                hookfunction(fn, function(target, ...)
                    if target == protectedScript then
                        return nil
                    end
                    return fn(target, ...)
                end)
            end)
        end
    end
end

-- 3. Identify executor (useful for logging / allow-listing)
local function checkExecutor()
    local success, name = pcall(identifyexecutor)
    if not success then
        return false
    end
    return name
end

-- 4. Lock down debug library functions commonly used to dump locals/upvalues
local function lockDebugLib()
    local blocked = {"traceback", "getinfo", "getlocal", "getupvalue"}
    for _, name in ipairs(blocked) do
        if debug[name] then
            debug[name] = function() return nil end
        end
    end
end

function AntiDump.Init()
    blockDump()
    lockDebugLib()
    if not checkEnvironment() then
        game:GetService("Players").LocalPlayer:Kick("Unauthorized access detected")
    end
end

function AntiDump.GetExecutor()
    return checkExecutor()
end

return AntiDump
