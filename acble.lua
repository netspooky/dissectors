--- Continuity Protocol Dissector <@netspooky> https://github.com/netspooky/dissectors ---
-- * This is a Wireshark/tshark dissector for the Apple Bluetooth Protocol dubbed "Continuity"
-- * It works by hooking the dissector table using essentially this filter:
--     `btcommon.eir_ad.entry.company_id == 0x004c`
--   to grab any Apple manufacturing data and dissect it from the Advertising Beacon.
-- * This dissector began as original research, and was enriched by other papers and protocol descriptions.
--   * See https://github.com/furiousMAC/continuity for a collection of resources regarding this protocol.
-- * There are some things about the protocol that have changed or extended, and newer message types have been identified.
-- * Not every field has been implemented yet because they require more research.
-- USAGE
-- * Install this dissector in your Wireshark plugin directory, then listen for bluetooth traffic using Wireshark.
-- * The display filter will be `acble`
-- * Packets can also be captured by an external interface, then read later using Wireshark or tshark too!
-- CHANGELOG
-- * 2023-04-26 - Fixed up some of the fields and added some more handlers, fixed endianness on some fields
-- * 2023-04-25 - Added base dissector

local messageTypes = {
    [0x01] = "Unknown 0x01",
    [0x02] = "iBeacon",
    [0x03] = "AirPrint",
    [0x04] = "Unknown 0x04",
    [0x05] = "AirDrop",
    [0x06] = "HomeKit",
    [0x07] = "Proximity Pairing",
    [0x08] = "Hey Siri",
    [0x09] = "AirPlay Target",
    [0x0A] = "AirPlay Source",
    [0x0B] = "MagicSwitch",
    [0x0C] = "Handoff",
    [0x0D] = "Tethering Target Presence",
    [0x0E] = "Tethering Source Presence",
    [0x0F] = "Nearby Action",
    [0x10] = "Nearby Info",
    [0x11] = "Unknown 0x11",
    [0x12] = "Find My",
    [0x13] = "Unknown 0x13",
    [0x14] = "Unknown 0x14",
    [0x15] = "Unknown 0x15",
    [0x16] = "Unknown 0x16",
}
local tfBool = {
    [0] = "False",
    [1] = "True"
}
-- Lua Rocks
function bitAnd(a, b)
    local result = 0
    local bitval = 1
    while a > 0 and b > 0 do
      if a % 2 == 1 and b % 2 == 1 then -- test the rightmost bits
          result = result + bitval      -- set the current bit
      end
      bitval = bitval * 2 -- shift left
      a = math.floor(a/2) -- shift right
      b = math.floor(b/2)
    end
    return result
end
acble = Proto("acble",  "Apple Continuity Protocol")
-- Protocol Declaration and general fields
acble.fields.tag     = ProtoField.uint8("acble.tag",     "Tag",      base.HEX,  messageTypes)
acble.fields.len     = ProtoField.uint8("acble.len",     "Length",   base.HEX)
acble.fields.tagdata = ProtoField.bytes("acble.tagdata", "Tag Data", base.SPACE)
acble.fields.dbgbyte = ProtoField.uint8("acble.dbgbyte", "[uint8]",  base.HEX)

-- 0x?? Unknown Message Types ----------------------------------------------\\--
acble.fields.unknown = ProtoField.bytes("acble.unknown", "Unknown Data",   base.SPACE)
function handlerUnknown(offset, dataLen, buffer, subtree, tagTree)
    tagTree:add(acble.fields.unknown, buffer(offset+2, dataLen))
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end

-- 0x01 Unknown 01 --------------------------------------------------------\\--
acble.fields.unknown01_d =  ProtoField.bytes("acble.unknown01.data", "Data", base.SPACE)
function Unknown0x01(offset, dataLen, buffer, subtree, tagTree)
    -- This message is mysterious, I think it's a bitfield of some sort.
    -- There's no data length field present, I've only ever seen 16 bytes.
    -- I've also never seen it chained with other messages so it may be safe to assume that buffer:len() == 17 is a decent check for now.
    if buffer:len() == 17 then
        tagTree:add(acble.fields.unknown01_d, buffer(offset+1, 16))
    end
    return 
end

-- 0x03 AirPrint ----------------------------------------------------------\\--
acble.fields.apr_addrtype =  ProtoField.uint8("acble.airprint.addrtype", "Address Type", base.HEX)
acble.fields.apr_rptype   =  ProtoField.uint8("acble.airprint.rptype",   "Resource Path Ty[e]", base.HEX)
acble.fields.apr_sectype  =  ProtoField.uint8("acble.airprint.sectype",  "Security Type", base.HEX)
acble.fields.apr_qidport  = ProtoField.uint16("acble.airprint.qidport",  "QID or TCP Port", base.HEX)
acble.fields.apr_ipaddr   =  ProtoField.bytes("acble.airprint.ipaddr",   "IP Address", base.SPACE) -- This is either IPv4 or IPv6
acble.fields.apr_power    =  ProtoField.uint8("acble.airprint.power",    "Power", base.HEX)
function AirPrint0x03(offset, dataLen, buffer, subtree, tagTree)
    tagTree:add(acble.fields.apr_addrtype, buffer(offset+2,1))
    tagTree:add(acble.fields.apr_rptype  , buffer(offset+3,1))
    tagTree:add(acble.fields.apr_sectype , buffer(offset+4,1))
    tagTree:add(acble.fields.apr_qidport , buffer(offset+5,2))
    tagTree:add(acble.fields.apr_ipaddr  , buffer(offset+7,16))
    tagTree:add(acble.fields.apr_power   , buffer(offset+23,1))
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end

-- 05 AirDrop --------------------------------------------------------------\\--
acble.fields.ad_padding =  ProtoField.bytes("acble.airdrop.padding", "Padding?", base.SPACE)
acble.fields.ad_version =  ProtoField.uint8("acble.airdrop.version", "Version",  base.DEC)
acble.fields.ad_appleid = ProtoField.uint16("acble.airdrop.appleid", "Apple ID", base.HEX)
acble.fields.ad_phone   = ProtoField.uint16("acble.airdrop.phone",   "Phone",    base.HEX)
acble.fields.ad_email   = ProtoField.uint16("acble.airdrop.email",   "Email",    base.HEX)
acble.fields.ad_email2  = ProtoField.uint16("acble.airdrop.email2",  "Email2",   base.HEX)
acble.fields.ad_suffix  =  ProtoField.uint8("acble.airdrop.suffix",  "Suffix",   base.DEC)
function Airdrop0x05(offset, dataLen, buffer, subtree, tagTree)
    tagTree:add(acble.fields.ad_padding, buffer(offset+2,8))
    tagTree:add(acble.fields.ad_version, buffer(offset+10,1))
    tagTree:add(acble.fields.ad_appleid, buffer(offset+11,2))
    tagTree:add(acble.fields.ad_phone,   buffer(offset+13,2))
    tagTree:add(acble.fields.ad_email,   buffer(offset+15,2))
    tagTree:add(acble.fields.ad_email2,  buffer(offset+17,2))
    tagTree:add(acble.fields.ad_suffix,  buffer(offset+19,1))
    offset = offset + 2 + dataLen -- Pack it up
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end -- Throw it back
end

-- 0x06 HomeKit -----------------------------------------------------------\\--
local HomeKitCategories = {
    [0x0000] = "Unknown",
    [0x0001] = "Other",
    [0x0002] = "Bridge",
    [0x0003] = "Fan",
    [0x0004] = "Garage Door Opener",
    [0x0005] = "Lightbulb",
    [0x0006] = "Door Lock",
    [0x0007] = "Outlet",
    [0x0008] = "Switch",
    [0x0009] = "Thermostat",
    [0x000A] = "Sensor",
    [0x000B] = "Security System",
    [0x000C] = "Door",
    [0x000D] = "Window",
    [0x000E] = "Window Covering",
    [0x000F] = "Programmable Switch",
    [0x0010] = "Range Extender",
    [0x0011] = "IP Camera",
    [0x0012] = "Video Doorbell",
    [0x0013] = "Air Purifier",
    [0x0014] = "Heater",
    [0x0015] = "Air Conditioner",
    [0x0016] = "Humidifier",
    [0x0017] = "Dehumidifier",
    [0x001C] = "Sprinklers",
    [0x001D] = "Faucets",
    [0x001E] = "Shower Systems",
}
acble.fields.hk_sts =  ProtoField.uint8("acble.homekit.status",    "Status Flags",    base.HEX)
acble.fields.hk_did =  ProtoField.bytes("acble.homekit.deviceid",  "Device ID",       base.SPACE)
acble.fields.hk_cat = ProtoField.uint16("acble.homekit.category",  "Category",        base.HEX,   HomeKitCategories)
acble.fields.hk_gsn = ProtoField.uint16("acble.homekit.gsn",       "State Number?",   base.HEX)
acble.fields.hk_cfn =  ProtoField.uint8("acble.homekit.confignum", "Config Number",   base.HEX)
acble.fields.hk_cvr =  ProtoField.uint8("acble.homekit.compver",   "Compatible Ver.", base.HEX)
function HomeKit0x06(offset, dataLen, buffer, subtree, tagTree)
    tagTree:add(acble.fields.hk_sts, buffer(offset+2,1))
    tagTree:add(acble.fields.hk_did, buffer(offset+3,6))
    tagTree:add_le(acble.fields.hk_cat, buffer(offset+9,2))
    tagTree:add(acble.fields.hk_gsn, buffer(offset+11,2))
    tagTree:add(acble.fields.hk_cfn, buffer(offset+13,1))
    tagTree:add(acble.fields.hk_cvr, buffer(offset+14,1))
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end

-- 0x07 Proximity Pairing --------------------------------------------------\\--
local ProxPairDeviceModels = {
    [0x2002] = "AirPods 1",
    [0x2003] = "Powerbeats3",
    [0x2005] = "BeatsX",
    [0x2006] = "Beats Solo 3",
    [0x200e] = "AirPods Pro",
    [0x200f] = "AirPods 2",
}
local ProxPairDeviceColors = {
    [0x00] = "White",
    [0x01] = "Black",
    [0x02] = "Red",
    [0x03] = "Blue",
    [0x04] = "Pink",
    [0x05] = "Gray",
    [0x06] = "Silver",
    [0x07] = "Gold",
    [0x08] = "Rose Gold",
    [0x09] = "Space Gray",
    [0x0A] = "Dark Blue",
    [0x0B] = "Light Blue",
    [0x0C] = "Yellow",
}
local ProxPairStatus = {
    [0x01] = "AirPods: Both out of case, not in ear",
    [0x02] = "Right in ear, Left in case",
    [0x03] = "AirPods: Right in ear, Left out of case",
    [0x0b] = "Both AirPods in ear",
    [0x11] = "AirPods: Right out of case, Left in case",
    [0x13] = "AirPods: Right in ear, Left in case",
    [0x21] = "Both taken out of ears, Pause Audio",
    [0x22] = "Left in ear, Right in case",
    [0x23] = "AirPods: Left in ear, Right out of case",
    [0x2b] = "Both AirPods in ear",
    [0x31] = "AirPods: Left out of case, Right in case",
    [0x33] = "AirPods: Left in ear, Right in case",
    [0x51] = "Case: Left out of case, Right in case",
    [0x53] = "Case: Left in ear, Right in case",
    [0x55] = "Case: Both AirPods in case",
    [0x71] = "Case: Right out of case, Left in case",
    [0x73] = "Case: Right in ear, Left in case",
    [0x75] = "Case: Both AirPods in case",
}
acble.fields.pp_undef       =  ProtoField.uint8("acble.proxpair.undef",       "Undefined",      base.HEX) -- Version?
acble.fields.pp_model       = ProtoField.uint16("acble.proxpair.model",       "Device Model",   base.HEX, ProxPairDeviceModels)
acble.fields.pp_status      =  ProtoField.uint8("acble.proxpair.status",      "Status",         base.HEX, ProxPairStatus)
acble.fields.pp_battery1    =  ProtoField.uint8("acble.proxpair.pp_battery1", "Battery 1",      base.HEX) -- Split this out into the two nibz
acble.fields.pp_battery2    =  ProtoField.uint8("acble.proxpair.pp_battery2", "Battery 2",      base.HEX) -- This one too
acble.fields.pp_lidopen     =  ProtoField.uint8("acble.proxpair.pp_lidopen",  "Lid Open",       base.HEX)
acble.fields.pp_devicecolor =  ProtoField.uint8("acble.proxpair.devicecolor", "Device Color",   base.HEX, ProxPairDeviceColors)
acble.fields.pp_encrypted   =  ProtoField.bytes("acble.proxpair.devicecolor", "Encrypted Data", base.SPACE)
function ProximityPairing0x07(offset, dataLen, buffer, subtree, tagTree)
    -- This one is weird, I know that there are some truncated messages that don't match this
    tagTree:add(acble.fields.pp_undef, buffer(offset+2,1)) -- should be 1
    tagTree:add_le(acble.fields.pp_model, buffer(offset+3,2))
    -- I don't know why but I have also seen some messages have one less byte than normal
    -- It might be device dependent but who knows
    tagTree:add(acble.fields.pp_status, buffer(offset+5,1))
    tagTree:add(acble.fields.pp_battery1, buffer(offset+6,1))
    tagTree:add(acble.fields.pp_battery2, buffer(offset+7,1))
    tagTree:add(acble.fields.pp_lidopen, buffer(offset+8,1))
    tagTree:add(acble.fields.pp_devicecolor, buffer(offset+9,1))
    tagTree:add(acble.fields.pp_undef, buffer(offset+10,1)) -- should be 0 (sometimes isn't tho, if so, it may have one less byte)
    if dataLen > 11 then
        tagTree:add(acble.fields.pp_encrypted, buffer(offset+11,16))
    end
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end

-- 0x08 Hey Siri -----------------------------------------------------------\\--
local HeySiriDeviceClasses = {
    [0x0002] = "iPhone",
    [0x0003] = "iPad",
    [0x0007] = "HomePod",
    [0x0009] = "MacBook",
    [0x000A] = "Watch",
}
local HeySiriWristConfidence = {
    [0x03] = "Not on Wrist",
    [0x1F] = "Wrist detection disabled",
    [0x3F] = "On Wrist",
}
acble.fields.hs_perphash    = ProtoField.uint16("acble.siri.perphash",    "Perceptual Hash",       base.HEX)
acble.fields.hs_snr         =  ProtoField.uint8("acble.siri.snr",         "Signal-to-Noise Ratio", base.HEX)
acble.fields.hs_confidence  =  ProtoField.uint8("acble.siri.confidence",  "Confidence",            base.HEX, HeySiriWristConfidence)
acble.fields.hs_deviceclass = ProtoField.uint16("acble.siri.deviceclass", "Device Class",          base.HEX, HeySiriDeviceClasses)
acble.fields.hs_randbyte    =  ProtoField.uint8("acble.siri.randbyte",    "Random Byte",           base.HEX)
function HeySiri0x08(offset, dataLen, buffer, subtree, tagTree)
    tagTree:add(acble.fields.hs_perphash, buffer(offset+2,2))
    tagTree:add(acble.fields.hs_snr, buffer(offset+4,1))
    tagTree:add(acble.fields.hs_confidence, buffer(offset+5,1))
    tagTree:add(acble.fields.hs_deviceclass, buffer(offset+6,2))
    tagTree:add(acble.fields.hs_randbyte, buffer(offset+8,1))
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end

-- 0x09 AirPlay Target -----------------------------------------------------\\--
acble.fields.ap_flags = ProtoField.uint8("acble.airplay.flags", "Flags",        base.HEX)
acble.fields.ap_cseed = ProtoField.uint8("acble.airplay.cseed", "Config Seed",  base.HEX)
acble.fields.ap_ipv4  =  ProtoField.ipv4("acble.airplay.ipv4",  "IPv4 Address", base.NONE)
function AirPlay0x09(offset, dataLen, buffer, subtree, tagTree)
    tagTree:add(acble.fields.ap_flags, buffer(offset+2,1))
    if dataLen > 1 then
        tagTree:add(acble.fields.ap_cseed, buffer(offset+3,1))
        tagTree:add(acble.fields.ap_ipv4, buffer(offset+4,4))
    end
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end

-- 0x0A Airplay Source -----------------------------------------------------\\--
acble.fields.ap_data = ProtoField.uint8("acble.airplay.data", "Data", base.HEX)
function AirPlaySource0x0A(offset, dataLen, buffer, subtree, tagTree)
    tagTree:add(acble.fields.ap_data, buffer(offset+2,1))
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end

-- 0x0B Magic Switch ------------------------------------------------------\\--
acble.fields.ms_data = ProtoField.uint16("acble.magicswitch.data", "Data", base.HEX)
acble.fields.ms_conf =  ProtoField.uint8("acble.magicswitch.conf", "Confidence", base.HEX)
function MagicSwitch0x0B(offset, dataLen, buffer, subtree, tagTree)
    tagTree:add(acble.fields.ms_data, buffer(offset+2,2))
    tagTree:add(acble.fields.ms_conf, buffer(offset+4,1))
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end

-- 0x0C Handoff ------------------------------------------------------------\\--
acble.fields.ho_copy     =  ProtoField.uint8("acble.handoff.copy",    "Clipboard Status?",    base.HEX) -- ?? or version
acble.fields.ho_seqnum   = ProtoField.uint16("acble.handoff.seqnum",  "Sequence Number (IV)", base.HEX)
acble.fields.ho_authtag  =  ProtoField.uint8("acble.handoff.authtag", "Auth Tag (AES-GCM)",   base.HEX)
acble.fields.ho_encdata  =  ProtoField.bytes("acble.handoff.encdata", "Encrypted Data",       base.SPACE)
function Handoff0x0C(offset, dataLen, buffer, subtree, tagTree)
    tagTree:add(acble.fields.ho_copy,    buffer(offset+2,1))
    tagTree:add_le(acble.fields.ho_seqnum,  buffer(offset+3,2))
    tagTree:add(acble.fields.ho_authtag, buffer(offset+5,1))
    tagTree:add(acble.fields.ho_encdata, buffer(offset+6,10))
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end

-- 0x0D Tethering Target Presence ------------------------------------------\\--
acble.fields.ttgt_icid = ProtoField.uint32("acble.tethtgt.icloudid", "Cloud ID", base.HEX)
function TetheringTarget0x0D(offset, dataLen, buffer, subtree, tagTree)
    tagTree:add(acble.fields.ttgt_icid, buffer(offset+2,4))
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end

-- 0x0E Tethering Source Presence ------------------------------------------\\--
local TetheringSourceCellTypes = {
    [0x00] = "4G (GSM)",
    [0x01] = "1xRTT",
    [0x02] = "GPRS",
    [0x03] = "EDGE",
    [0x04] = "3G (EV-DO)",
    [0x05] = "3G",
    [0x06] = "4G",
    [0x07] = "LTE",
}
acble.fields.tsrc_vers =  ProtoField.uint8("acble.tethsrc.version",  "Version",      base.HEX)
acble.fields.tsrc_flag =  ProtoField.uint8("acble.tethsrc.flags",    "Flags",        base.HEX)
acble.fields.tsrc_batt =  ProtoField.uint8("acble.tethsrc.battery",  "Battery %",    base.HEX)
acble.fields.tsrc_type = ProtoField.uint16("acble.tethsrc.celltype", "Cell Service", base.HEX, TetheringSourceCellTypes)
acble.fields.tsrc_bars =  ProtoField.uint8("acble.tethsrc.cellbars", "Cell Signal",  base.HEX)
function TetheringSource0x0E(offset, dataLen, buffer, subtree, tagTree)
    tagTree:add(acble.fields.tsrc_vers, buffer(offset+2,1))
    tagTree:add(acble.fields.tsrc_flag, buffer(offset+3,1))
    tagTree:add(acble.fields.tsrc_batt, buffer(offset+4,1))
    tagTree:add(acble.fields.tsrc_type, buffer(offset+5,2))
    tagTree:add(acble.fields.tsrc_bars, buffer(offset+7,1))
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end

-- 0x0F Nearby Action ------------------------------------------------------\\--
local NearbyActionTypes = {
    [0x01] = "Apple TV Setup",
    [0x04] = "Mobile Backup",
    [0x05] = "Watch Setup",
    [0x06] = "Apple TV Pair",
    [0x07] = "Internet Relay",
    [0x08] = "WiFi Password",
    [0x09] = "iOS Setup",
    [0x0A] = "Repair",
    [0x0B] = "Speaker Setupd",
    [0x0C] = "Apple Pay",
    [0x0D] = "Whole Home Audio Setup",
    [0x0E] = "Developer Tools Pairing Request",
    [0x0F] = "Answered Call",
    [0x10] = "Ended Call",
    [0x11] = "DD Ping",
    [0x12] = "DD Pong",
    [0x13] = "Remote Auto Fill",
    [0x14] = "Companion Link Proximity",
    [0x15] = "Remote Management",
    [0x16] = "Remote Auto Fill Pong",
    [0x17] = "Remote Display",
}
local NearbyActionDeviceClass = {
    [0x2] ="iPhone",
    [0x4] ="iPod",
    [0x6] ="iPad",
    [0x8] ="Audio accessory (HomePod)",
    [0xA] ="Mac",
    [0xC] ="AppleTV",
    [0xE] ="Watch",
}
acble.fields.na_flags   =  ProtoField.uint8("acble.nearbyaction.flags",   "Action Flags", base.HEX)
acble.fields.na_type    =  ProtoField.uint8("acble.nearbyaction.type",    "Action Type",  base.HEX, NearbyActionTypes)
acble.fields.na_authtag = ProtoField.uint24("acble.nearbyaction.authtag", "Auth Tag",     base.HEX)
acble.fields.na_device  =  ProtoField.uint8("acble.nearbyaction.device",  "Device",      base.HEX, NearbyActionDeviceClass)
function NearbyAction0x0F(offset, dataLen, buffer, subtree, tagTree)
    tagTree:add(acble.fields.na_flags, buffer(offset+2,1))
    tagTree:add(acble.fields.na_type, buffer(offset+3,1))
    if dataLen > 2 then
        tagTree:add(acble.fields.na_authtag, buffer(offset+4,3))
        if dataLen > 5 then
            tagTree:add(acble.fields.na_device, buffer(offset+7,1))
        end
    end
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end

-- 0x10 Nearby Info --------------------------------------------------------\\--
local NearbyInfoActivityLevels = {
    [0x00] = "Activity level is not known",
    [0x01] = "Activity reporting is disabled",
    [0x03] = "User is idle",
    [0x05] = "Audio is playing with the screen off",
    [0x07] = "Screen is on",
    [0x09] = "Screen on and video playing",
    [0x0A] = "Watch is on wrist and unlocked",
    [0x0B] = "Recent user interaction",
    [0x0D] = "User is driving a vehicle",
    [0x0E] = "Phone call or Facetime",
}
acble.fields.nbi_activitylevel =  ProtoField.uint8("acble.nbi.activity_level", "Activity Level", base.HEX, NearbyInfoActivityLevels)
acble.fields.nbi_information   =  ProtoField.uint8("acble.nbi.information",    "Information",    base.HEX)
acble.fields.nbi_authtag       = ProtoField.uint24("acble.nbi.authtag",        "Auth Tag",       base.HEX)
acble.fields.nbi_unknown       =  ProtoField.uint8("acble.nbi.unknown",        "Unknown",        base.HEX)
function NearbyInfo0x10(offset, dataLen, buffer, subtree, tagTree)
    -- This one has some extended messages longer than 6 bytes but I haven't seen them
    tagTree:add(acble.fields.nbi_activitylevel, buffer(offset+2,1), bitAnd(buffer(offset+2,1):uint(),0x0F)) -- Only using the bottom 4 bits for now
    tagTree:add(acble.fields.nbi_information, buffer(offset+3,1))
    if dataLen == 3 then
        tagTree:add(acble.fields.nbi_unknown, buffer(offset+4,1)) -- For a 3 byte version of NI
    elseif dataLen == 4 then
        tagTree:add(acble.fields.nbi_unknown, buffer(offset+4,1)) -- For a 4 byte version of NI
        tagTree:add(acble.fields.nbi_unknown, buffer(offset+5,1)) -- For a 4 byte version of NI
    elseif dataLen > 4 then
        tagTree:add(acble.fields.nbi_authtag, buffer(offset+4,3)) -- For 5+
        if dataLen > 5 then
            tagTree:add(acble.fields.nbi_unknown, buffer(offset+7,1)) -- Idk why but there is sometimes a random byte after the auth tag, seems like flags?
        end
    end
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end

-- 0x12 FindMy -------------------------------------------------------------\\--
local FindMyStatus = {
    [0x00] = "Owner did not connect within key rotation period (15 min.)",
    [0xe4] = "Owner connected with key roation period, Battery Critically Low",
    [0xa4] = "Owner connected with key roation period, Battery Low",
    [0x64] = "Owner connected with key roation period, Battery Medium",
    [0x24] = "Owner connected with key roation period, Battery Full",
}
local FindMyPubkeyBits = {
    [0x00] = "bits 6 & 7 not set in public key",
    [0x01] = "bit 6 set in public key",
    [0x02] = "bit 7 set in public key",
    [0x03] = "bits 6 & 7 set in public key",
}
acble.fields.findmy_status     = ProtoField.uint8("acble.findmy.status",     "Status",      base.HEX, FindMyStatus)
acble.fields.findmy_pubkey     = ProtoField.bytes("acble.findmy.pubkey",     "PubKey",      base.SPACE)
acble.fields.findmy_pubkeybits = ProtoField.uint8("acble.findmy.pubkeybits", "PubKey Bits", base.HEX, FindMyPubkeyBits)
acble.fields.findmy_hint       = ProtoField.uint8("acble.findmy.hint",       "Hint",        base.HEX)
acble.fields.findmy_unknown    = ProtoField.uint8("acble.findmy.unknown",    "Unknown",     base.HEX)
function FindMy0x12(offset, dataLen, buffer, subtree, tagTree)
    tagTree:add(acble.fields.findmy_status, buffer(offset+2,1))
    if dataLen == 2 then
        tagTree:add(acble.fields.findmy_unknown, buffer(offset+3,1))
    end
    if dataLen > 25 then
        tagTree:add(acble.fields.findmy_pubkey, buffer(offset+3,22))
        tagTree:add(acble.fields.findmy_pubkeybits, buffer(offset+25,1))
        tagTree:add(acble.fields.findmy_hint, buffer(offset+26,1))
    end
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end
-- 0x16 Unknown Message ----------------------------------------------------\\--
acble.fields.unknown16_1 = ProtoField.uint16("acble.unknown16.f1", "Unknown Field 1",   base.HEX)
acble.fields.unknown16_2 =  ProtoField.bytes("acble.unknown16.f2", "Unknown Field 2",   base.SPACE)
function Unknown0x16(offset, dataLen, buffer, subtree, tagTree)
    tagTree:add(acble.fields.unknown16_1, buffer(offset+2, 2))
    tagTree:add(acble.fields.unknown16_2, buffer(offset+4, dataLen-2))
    offset = offset + 2 + dataLen
    if offset < buffer:len() then parseTags(buffer, subtree, offset) else return end
end

function parseTags(buffer, subtree, offset)
    local tagValue = buffer(offset,1):uint()
    local dataLen = buffer(offset+1,1):uint()
    local tagtree = subtree:add(acble, buffer(offset, dataLen+2), messageTypes[tagValue])
    tagtree:add(acble.fields.tag, buffer(offset,1))
    tagtree:add(acble.fields.len, buffer(offset+1,1))
    if tagValue == 0x01 then
        Unknown0x01(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x02 then
        handlerUnknown(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x03 then
        AirPrint0x03(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x04 then
        handlerUnknown(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x05 then
        Airdrop0x05(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x06 then
        HomeKit0x06(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x07 then
        ProximityPairing0x07(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x09 then
        AirPlay0x09(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x0A then
        AirPlaySource0x0A(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x0B then 
        MagicSwitch0x0B(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x0C then
        Handoff0x0C(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x0D then
        TetheringTarget0x0D(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x0E then
        TetheringSource0x0E(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x0F then
        NearbyAction0x0F(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x10 then
        NearbyInfo0x10(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x12 then
        FindMy0x12(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x13 then
        handlerUnknown(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x14 then
        handlerUnknown(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x15 then
        handlerUnknown(offset, dataLen, buffer, subtree, tagtree)
    elseif tagValue == 0x16 then
        Unknown0x16(offset, dataLen, buffer, subtree, tagtree)
    else
        --handlerUnknown(offset, dataLen, buffer, subtree, tagtree) -- Use at own risk :)
        return
    end
end

function acble.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end
  pinfo.cols.protocol = acble.name
  local subtree = tree:add(acble, buffer(), "Apple Continuity Protocol")
  parseTags(buffer, subtree, 0)
end

DissectorTable.get("btcommon.eir_ad.manufacturer_company_id"):add(0x004c, acble)
