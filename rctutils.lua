--
-- Utility functions for rctserial.lua
--
-- Copyright 2021-2022 Stefan Valouch (svalouch)
-- SPDX-License-Identifier: GPL-3.0-only
--

function CRC16(data)
    -- data: string
    print('crc input: ' .. hex_dump(data))
    local crcsum = 0xFFFF
    local polynom = 0x1021  -- CCITT Polynom

    if (data:len() % 2 == 1) then
        data = data .. '\0'
    end

    for i = 1, #data do
        local byte = data:byte(i)
        crcsum = crcsum ^ byte
        for j = 1, 8 do
            crcsum = bit.lshift(crcsum, 1)
            local k = bit.band(crcsum, 0x7FFF0000)
            if k ~= 0 then
                crcsum = bit.band(crcsum, 0x0000FFFF) ^ polynom
            end
        end
    end
    return crcsum
end


-- function CRC16_new(byte_array)
--     local POLY = 0x1021
--
--     local function hash(crc, byte)
--         for i = 0, 7 do
--             local lsb = bit32.extract(byte, 7 - i) -- Take the lsb
--             local msb = bit32.extract(crc, 15, 1) -- msb
--             crc = crc << 1 -- Remove the lsb of crc
--             if lsb ^ msb == 1 then crc = crc ^ POLY end
--         end
--         return crc
--     end
--
--     local crc = 0xffff
--     for i in ipairs(byte_array) do
--         crc = hash(crc, byte_array[i])
--     end
--
--     return bit32.extract(crc, 0, 16)
-- end

function get_command_name(command)
        if command == 0x01 then name = 'READ'
    elseif command == 0x02 then name = 'WRITE'
    elseif command == 0x03 then name = 'LONG WRITE'
    elseif command == 0x05 then name = 'RESPONSE'
    elseif command == 0x06 then name = 'LONG RESPONSE'
    elseif command == 0x08 then name = 'READ PERIODICALLY'
    elseif command == 0x41 then name = 'PLANT READ'
    elseif command == 0x3c then name = 'EXTENSION'
    else name = 'Unknown'
    end
    return name
end

function cmd_known(cmd)
        if cmd == 0x01 then return true
    elseif cmd == 0x02 then return true
    elseif cmd == 0x03 then return true
    elseif cmd == 0x03 then return true
    elseif cmd == 0x05 then return true
    elseif cmd == 0x06 then return true
    elseif cmd == 0x08 then return true
    elseif cmd == 0x41 then return true
    elseif cmd == 0x42 then return true
    elseif cmd == 0x43 then return true
    else return false
    end
end
function cmd_is_plant(cmd)
        if cmd == 0x41 then return true
    elseif cmd == 0x42 then return true
    elseif cmd == 0x43 then return true
    else return false
    end
end
function cmd_is_long(cmd)
        if cmd == 0x03 then return true
    elseif cmd == 0x06 then return true
    elseif cmd == 0x43 then return true
    else return false
    end
end

function hex_dump (str)
    local len = string.len( str )
    local dump = ""
    local hex = ""
    local asc = ""

    for i = 1, len do
        if 1 == i % 8 then
            dump = dump .. hex .. asc .. "\n"
            hex = string.format( "%04x: ", i - 1 )
            asc = ""
        end

        local ord = string.byte( str, i )
        hex = hex .. string.format( "%02x ", ord )
        if ord >= 32 and ord <= 126 then
            asc = asc .. string.char( ord )
        else
            asc = asc .. "."
        end
    end

    return dump .. hex .. string.rep( "   ", 8 - len % 8 ) .. asc
end
