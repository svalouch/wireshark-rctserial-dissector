-- Dissector for the "Serial Communication Protocol" by "RCT Power GmbH"
-- For more information, see https://github.com/svalouch/python-rctclient and the accompanied documentation.
--
-- Copyright 2021-2022 Stefan Valouch (svalouch)
-- SPDX-License-Identifier: GPL-3.0-only
--
-- Installation: Place the files "rctserial.lua", "rctutils.lua" and "rctdata.lua" in the directory
-- $HOME/.local/lib/wireshark/plugins/ and start Wireshark. It may be required to select a TCP stream once and select
-- "Decode as..." from the context-menu and remove everything but "RCTSERIAL" from the list.

require('rctdata')   -- bulk data
require('rctutils')  -- utility functions

rctserial_protocol = Proto("rctserial", "RCT Power GmbH - Serial Communication Protocol")

START_TOKEN = '+'
ESCAPE_TOKEN = '-'

Frame = {}
function Frame:new()
    self.__buffer = ''
    self.__consumed = 0
    self.__escaping = false
    self.__frame_header_length = 7
    self.__address = 0
    self.cmd = 0
    self.id = 0
    self.frame_length = 0
    self.complete = true
    self.crc_ok = false
    self.crc16 = ''
    self.data = ''

    self.skipped_from_start = 0  -- amount of bytes skipped before finding the start

    self.pos_command = 0    -- position of command
    self.pos_length = 0     -- position of length
    self.length_length = 1  -- how many bytes the length is long
    self.pos_address = 0    -- position of address
    self.pos_oid = 0        -- position of OID
    self.pos_data = 0       -- position of start of data
    self.length_data = 0    -- length of data
    self.pos_crc = 0        -- position of crc

    return self
end

function Frame:parse(bytes)

    local len = 0
    for i = 0, bytes:len(), 1 do
        self.__consumed = self.__consumed + 1
        len = len + 1
        c = bytes:raw(i, 1)

        if self.__buffer:len() == 0 then
            if c == START_TOKEN then
                -- print('START')
                self.__buffer = self.__buffer .. c
            end
            self.skipped_from_start = self.skipped_from_start + 1
            goto continue
        end

        if self.__escaping then
            self.__escaping = false
        else
            if c == ESCAPE_TOKEN then
                self.__escaping = true
                goto continue
            end
        end

        self.__buffer = self.__buffer .. c

        local blen = self.__buffer:len()

        if blen == 2 then
            self.pos_command = len - 1
            self.cmd = Struct.unpack('B', self.__buffer:sub(2, 3))
            if not cmd_known(self.cmd) then
                return false, len, 'Command unknown'
            end
            if self.cmd == 0x3c then
                return false, len, 'Extension'
            end
            if cmd_is_plant(self.cmd) then
                self.__frame_header_length = self.__frame_header_length + 4
            end
            if cmd_is_long(self.cmd) then
                self.__frame_header_length = self.__frame_header_length + 1
            end
        elseif blen == self.__frame_header_length then
            local data_length = 0
            local address_idx = 0
            self.pos_length = self.pos_command + 1
            if cmd_is_long(self.cmd) then
                self.length_length = 2
                data_length = Struct.unpack('>H', self.__buffer:sub(3, 5))
                address_idx = 4
            else
                self.length_length = 1
                data_length = Struct.unpack('>B', self.__buffer:sub(3, 4))
                address_idx = 3
            end

            local oid_idx = address_idx
            if cmd_is_plant(self.cmd) then
                self.frame_length = (self.__frame_header_length - 8) + data_length + 2
                self.pos_address = self.skipped_from_start + address_idx
                self.__address = Struct.unpack('>I', self.__buffer:sub(address_idx + 1, address_idx + 1 + 4))
                oid_idx = oid_idx + 4
            else
                self.frame_length = (self.__frame_header_length - 4) + data_length + 2
            end
            self.pos_oid = self.skipped_from_start + oid_idx - 1
            self.id = Struct.unpack('>I', self.__buffer:sub(oid_idx + 1, oid_idx + 1 + 4))
        elseif self.frame_length > 0 and blen == self.frame_length then
            self.complete = true

            self.pos_crc = self.skipped_from_start + self.__buffer:len() - 3
            self.crc16 = Struct.unpack('>H', self.__buffer:sub(-3))
            -- calc_crc16 = self.__buffer:sub(2, -3)
            -- print(hex_dump(calc_crc16))
            calc_crc16 = CRC16(self.__buffer:sub(2, -3))
            self.crc_ok = calc_crc16 == self.crc16
            self.pos_data = self.skipped_from_start + self.__frame_header_length - 1
            self.data = self.__buffer:sub(self.__frame_header_length + 1, -3)
            self.length_data = self.data:len()
            return true, len, 'OK'
        end
        ::continue::
    end
    return true, len, 'OK'
end

-- Fields to be used later
frame_command = ProtoField.char("rctserial.command", "command", base.HEX, COMMANDS)
frame_length = ProtoField.uint16('rctserial.frame_length', 'Length', base.DEC)
frame_oid = ProtoField.uint32("rctserial.oid", "OID", base.HEX)
frame_crc = ProtoField.uint16("rctserial.crc", "CRC", base.HEX)

frame_value_hex = ProtoField.string("rctserial.value_hex", "Value (hexdump)")
frame_value_string = ProtoField.string("rctserial.value_string", "Value (string)")
frame_value_int = ProtoField.int32("rctserial.value_int", "Value (uint)")
frame_value_uint = ProtoField.uint32("rctserial.value_uint", "Value (uint)")
frame_value_float = ProtoField.float("rctserial.value_float", "Value (float)")
frame_value_enum = ProtoField.uint8("rctserial.value_float", "Value (enum)")

rctserial_protocol.fields = {
    frame_command, frame_length, frame_oid, frame_crc, frame_value_hex, frame_value_float, frame_value_int,
    frame_value_uint, frame_value_enum
}

-- Expert fields add additional data and status information
ef_checksum = ProtoExpert.new('rctclient.checksum.invalid', 'Checksum is not valid', expert.group.CHECKSUM, expert.severity.ERROR)
ef_command_unknown = ProtoExpert.new('rctclient.command.unknown', 'Unknown command', expert.group.MALFORMED, expert.severity.ERROR)
ef_command_extension = ProtoExpert.new('rctclient.command.extension', 'Extension command', expert.group.UNDECODED, expert.severity.WARN)
ef_oid_unknown = ProtoExpert.new('rctclient.oid.unknown', 'Unknown OID', expert.group.UNDECODED, expert.severity.WARN)
ef_parse_error_unknown = ProtoExpert.new('rctclient.parse_error', 'Parse error', expert.group.MALFORMED, expert.severity.ERROR)

rctserial_protocol.experts = {
    ef_checksum, ef_command_unknown, ef_command_extension, ef_oid_unknown, ef_parse_error_unknown
}

function rctserial_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = rctserial_protocol.name

    local start = 0
    f = Frame:new()

    while start < buffer:len() do
        if f == nil then f = Frame:new() end

        print('Start: ' .. start .. '/' .. buffer:len())
        local ok, consumed, msg = f:parse(buffer:bytes(start))
        print('Frame: ' .. tostring(ok) .. ' plen: ' .. consumed .. ' msg: ' .. msg)
        print('pos_command: ' .. f.pos_command .. ' pos_oid: ' .. f.pos_oid)

        if ok then
            if f.complete then
                local command_name = get_command_name(buffer(start + f.pos_command, 1):le_int())
                local oid_name = 'UNKNOWN'
                if OID[f.id] ~= nil then
                    oid_name = OID[f.id].name
                end

                local subtree = tree:add(rctserial_protocol, buffer(start, consumed), string.format('RCTSerial Frame (%s %s)', command_name, oid_name))
                -- command
                subtree:add_le(frame_command, buffer(start + f.pos_command, 1)):append_text(" (" .. command_name .. ")")
                -- length
                subtree:add_le(frame_length, buffer(start + f.pos_length, f.length_length))
                -- address TODO
                -- OID
                local f_oid = subtree:add(frame_oid, buffer(start + f.pos_oid, 4)):append_text(" (" .. oid_name .. ")")
                if oid_name == 'UNKNOWN' then
                    f_oid:add_proto_expert_info(ef_oid_unknown, 'OID not known, check for updates')
                end

                -- Value
                if f.cmd == 0x05 or f.cmd == 0x06 then
                    if OID[f.id] ~= nil then
                        dtype = OID[f.id].type
                        if dtype == 'FLOAT' then
                            subtree:add(frame_value_float, buffer(start + f.pos_data, f.length_data))
                        elseif dtype == 'INT8' or dtype == 'INT16' or dtype == 'INT32' then
                            subtree:add(frame_value_int, buffer(start + f.pos_data, f.length_data))
                        elseif dtype == 'UINT8' or dtype == 'UINT16' or dtype == 'UINT32' then
                            subtree:add(frame_value_uint, buffer(start + f.pos_data, f.length_data))
                        elseif dtype == 'ENUM' then
                            subtree:add(frame_value_enum, buffer(start + f.pos_data, f.length_data))
                        elseif dtype == 'STRING' then
                            subtree:add(frame_value_string, buffer(start + f.pos_data, f.length_data))
                        end
                    else
                        subtree:add(frame_value_hex, buffer(start + f.pos_data, f.length_data))
                    end
                end
                -- CRC
                local f_csum = subtree:add(frame_crc, buffer(start + f.pos_crc, 2))
                -- CRC function is still br0ken
                --if not f.crc_ok then
                --    f_csum:add_tvb_expert_info(ef_checksum, buffer(start + f.pos_crc, 2), 'Invalid, expected ' .. string.format('0x%x', f.crc16))
                --end
            else
                print('Frame does not end at segment, not sure what to do')
            end
            f = nil
        else
            if msg == 'Command unknown' then
                local subtree = tree:add(rctserial_protocol, buffer(start, consumed), "RCTSerial Frame (unknown command)")
                local f_cmd = subtree:add_le(frame_command, buffer(start + f.pos_command, 1))
                f_cmd:add_proto_expert_info(ef_command_unknown, 'Unknown command ' .. string.format('0x%x', string.byte(buffer:raw(start + f.pos_command, 1))))
            elseif msg == 'Extension' then
                local subtree = tree:add(rctserial_protocol, buffer(start, consumed), "RCTSerial Frame (Extension)")
                local f_cmd = subtree:add_le(frame_command, buffer(start + f.pos_command, 1))
                f_cmd:add_proto_expert_info(ef_command_extension, 'Extension command, cannot decode')
            else
                local subtree = tree:add(rctserial_protocol, buffer(start, consumed), "RCTSerial Frame (Unknown error)")
                subtree:add_proto_expert_info(ef_parse_error_unknown, msg)
            end
            f = nil
        end
        start = start + consumed
    end
end


local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8899, rctserial_protocol)
