-- Dissector for BGB Emulator Link Cable Protocol - by netspooky - Date: 20211009
-- Tested on version 1.4, should also work for latest (1.5.2)
-- Default BGB listener port is 8765
-- Reference: https://bgb.bircd.org/bgblink.html

--- Bit Maps -------------------------------------------------------------------

local generic_bf = {
    -- A generic bitfield for options
    [0] = "Nope",
    [1] = "Yup"
}

local status_bf2 = {
    [0] = "No Reconnect",
    [1] = "Supports Reconnect"
}

local sync1_cv0 = {
    [0] = "SOMETHING IS TERRIBLY WRONG???? 0???",
    [1] = "Is 1"
}

local buttonMap = {
    [0] = "RIGHT",
    [1] = "LEFT",
    [2] = "UP",
    [3] = "DOWN",
    [4] = "A",
    [5] = "B",
    [6] = "SELECT",
    [7] = "START"
}

--- Generic Fields -------------------------------------------------------------

bgblink = Proto("bgblink","BGB Link Protocol")
bgblink.fields.command   = ProtoField.uint8("bgblink.command", "Command", base.STRING)
bgblink.fields.data1     = ProtoField.uint8("bgblink.d1", "Data 1", base.HEX)
bgblink.fields.data2     = ProtoField.uint8("bgblink.d2", "Data 2", base.HEX)
bgblink.fields.data3     = ProtoField.uint8("bgblink.d3", "Data 3", base.HEX)
bgblink.fields.tstamp    = ProtoField.uint32("bgblink.timestamp", "Timestamp", base.DEC)

--- Command Specific Fields ----------------------------------------------------

-- 0x01 - Version
bgblink.fields.version   = ProtoField.string("bgblink.version", "Version", base.ASCII)

-- 0x65 (101) - Joypad
bgblink.fields.btnnum    = ProtoField.uint8("bgblink.btnnum", "Button Number", base.DEC, buttonMap)
bgblink.fields.btnpress  = ProtoField.bool("bgblink.btnpress", "Button Pressed", base.BOOLEAN)

-- 0x68 (104) - Sync1
bgblink.fields.sync1_dv  = ProtoField.uint8("bgblink.sync1_dv", "Sync1 Data Value", base.HEX)
bgblink.fields.sync1_cv0 = ProtoField.uint8("bgblink.sync1_cv0", "Must be 1", base.DEC, sync1_cv0, 0x1)
bgblink.fields.sync1_cv1 = ProtoField.uint8("bgblink.sync1_cv1", "High Speed?", base.DEC, generic_bf, 0x2)
bgblink.fields.sync1_cv2 = ProtoField.uint8("bgblink.sync1_cv2", "Double Speed?", base.DEC, generic_bf, 0x4)

-- 0x69 (105) - Sync2
bgblink.fields.sync2_dv  = ProtoField.uint8("bgblink.sync2_dv", "Sync2 Data Value", base.HEX)
bgblink.fields.sync2_cv  = ProtoField.uint8("bgblink.sync2_cv", "Sync2 Ctrl Value", base.HEX)

-- 0x6C (108) - Status
bgblink.fields.status_b0 = ProtoField.uint8("bgblink.status_b0", "Running?", base.DEC, generic_bf, 0x1)
bgblink.fields.status_b1 = ProtoField.uint8("bgblink.status_b1", "Paused?", base.DEC, generic_bf, 0x2)
bgblink.fields.status_b2 = ProtoField.uint8("bgblink.status_b1", "Extended Features", base.DEC, status_bf2, 0x4)

function bgblink.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "BGB-LINK"
    local subtree = tree:add(bgblink, buffer(), "BGB Link Protocol")
    local buff_len = buffer:len()
    if buff_len == 8 then
        local cmd = buffer(0, 1):uint() -- Command
        local d1  = buffer(1, 1) -- Data 1
        local d2  = buffer(2, 1) -- Data 2
        local d3  = buffer(3, 1) -- Data 3
        local ts  = buffer(4, 4):le_uint() -- Timestamp
        if cmd == 0x01 then
            subtree:add(bgblink.fields.command, cmd, "Command: Version")
            subtree:add(bgblink.fields.version, d1:uint() .. "." .. d2:uint())
            subtree:add(bgblink.fields.data3, d3)
        elseif cmd == 0x65 then
            subtree:add(bgblink.fields.command, cmd, "Command: Joypad")
            subtree:add(bgblink.fields.btnnum, d1:bitfield(5,3)) -- Indexed from MSB = 0
            subtree:add(bgblink.fields.btnpress, d1:bitfield(4,1))
            subtree:add(bgblink.fields.data2, d2)
            subtree:add(bgblink.fields.data3, d3)
        elseif cmd == 0x68 then
            subtree:add(bgblink.fields.command, cmd, "Command: Sync1 - Byte from Peripheral")
            subtree:add(bgblink.fields.sync1_dv, d1)
            subtree:add(bgblink.fields.sync1_cv0, d2)
            subtree:add(bgblink.fields.sync1_cv1, d2)
            subtree:add(bgblink.fields.sync1_cv2, d2)
            subtree:add(bgblink.fields.data3, d3)
        elseif cmd == 0x69 then
            subtree:add(bgblink.fields.command, cmd, "Command: Sync2 - Passive Transfer Response")
            subtree:add(bgblink.fields.sync2_dv, d1)
            subtree:add(bgblink.fields.sync2_cv, d2)
            subtree:add(bgblink.fields.data3, d3)
        elseif cmd == 0x6A then
            if d1:uint() == 1 then 
                subtree:add(bgblink.fields.command, cmd, "Command: Sync3 - Received Active Transfer")
                subtree:add(bgblink.fields.data1, d1)
                subtree:add(bgblink.fields.data2, d2)
                subtree:add(bgblink.fields.data3, d3)
            else
                subtree:add(bgblink.fields.command, cmd, "Command: Sync3 - Updating Timestamp")
                subtree:add(bgblink.fields.data1, d1)
                subtree:add(bgblink.fields.data2, d2)
                subtree:add(bgblink.fields.data3, d3)
            end
        elseif cmd == 0x6C then
            subtree:add(bgblink.fields.command, cmd, "Command: Status")
            subtree:add(bgblink.fields.status_b0, d1)
            subtree:add(bgblink.fields.status_b1, d1)
            subtree:add(bgblink.fields.status_b2, d1)
        elseif cmd == 0x6D then
            subtree:add(bgblink.fields.command, cmd, "Command: Want Disconnect (BGB 1.5.2)")
        else
            subtree:add(bgblink.fields.command, cmd, "Command: UNKNOWN")
            subtree:add(bgblink.fields.data1, d1)
            subtree:add(bgblink.fields.data2, d2)
            subtree:add(bgblink.fields.data3, d3)
        end
        subtree:add(bgblink.fields.tstamp, ts)
    end
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(8765, bgblink)
