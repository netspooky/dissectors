-- Postgres Stats Collector Protocol Dissector by @netspooky 20210817
--
--   This is an internal postgres protocol used for updating the database
--   every time an action is taken on the database. It changes with every 
--   version, use at your own risk. Also the port is different every time
--   it runs, and there's no magic values that make it easy to track.
--
--   Run this to figure out what port it's running on. Look for postgres.
--   $ sudo ss -u -a -p
--   Then update the last line in this dissector that says "udp_table:add(48264,pgstats)"

-- Declaring Protocol Name
pgstats = Proto("pgstats","pg stats protocol")

pgstats.fields.MessageType  = ProtoField.uint32("pgstats.messagetype", "Message Type", base.STRING, MessageType)
pgstats.fields.MessageLen   = ProtoField.uint32("pgstats.length", "Message Length", base.DEC)

-- Message 1 - Inquiry
pgstats.fields.M1ClockTime   = ProtoField.uint64("pgstats.m1.clocktime", "Clock Time ", base.HEX)
pgstats.fields.M1CutoffTime  = ProtoField.uint64("pgstats.m1.cutofftime", "Cutoff Time", base.HEX)
pgstats.fields.M1Oid         = ProtoField.uint32("pgstats.m1.oid", "Database ID", base.DEC)

-- Message 2 - Table Stats
pgstats.fields.M2Oid              = ProtoField.uint32("pgstats.m2.oid", "Database ID", base.DEC)
pgstats.fields.M2NumEntries       = ProtoField.uint32("pgstats.m2.numentries", "Number of Entries", base.DEC)
pgstats.fields.M2xactcommit       = ProtoField.uint32("pgstats.m2.xactcommit", "Exact Commit", base.HEX)
pgstats.fields.M2xactrollback     = ProtoField.uint32("pgstats.m2.xactrollback", "Exact Rollback", base.HEX)
pgstats.fields.M2blkreadtime      = ProtoField.uint64("pgstats.m2.blkreadtime", "Block Read Time", base.HEX)
pgstats.fields.M2blkwritetime     = ProtoField.uint64("pgstats.m2.blkwritetime", "Block Write Time", base.HEX)
pgstats.fields.M2teOID            = ProtoField.uint32("pgstats.m2.te.oid", "Table Entry OID", base.DEC)
pgstats.fields.M2teUNK1           = ProtoField.uint32("pgstats.m2.te.unk1", "Table Entry Unknown Field 1", base.HEX)
pgstats.fields.numscans           = ProtoField.uint64("pgstats.m2.te.numscans", "Number of Scans", base.DEC)
pgstats.fields.tuplesreturned     = ProtoField.uint64("pgstats.m2.te.tuplesreturned", "Tuples Returned", base.DEC)
pgstats.fields.tuplesfetched      = ProtoField.uint64("pgstats.m2.te.tuplesfetched", "Tuples Fetched", base.DEC)
pgstats.fields.tuplesinserted     = ProtoField.uint64("pgstats.m2.te.tuplesinserted", "Tuples Inserted", base.DEC)
pgstats.fields.tuplesupdated      = ProtoField.uint64("pgstats.m2.te.tuplesupdated", "Tuples Updated", base.DEC)
pgstats.fields.tuplesdeleted      = ProtoField.uint64("pgstats.m2.te.tuplesdeleted", "Tuples Deleted", base.DEC)
pgstats.fields.tupleshotupdated   = ProtoField.uint64("pgstats.m2.te.tupleshotupdated", "Tuples Hot Updated", base.DEC)
pgstats.fields.truncated          = ProtoField.uint64("pgstats.m2.te.truncated", "Truncated (Bool)", base.DEC)
pgstats.fields.deltalivetuples    = ProtoField.uint64("pgstats.m2.te.deltalivetuples", "Delta Live Tuples", base.DEC)
pgstats.fields.deltadeadtuples    = ProtoField.uint64("pgstats.m2.te.deltadeadtuples", "Delta Dead Tuples", base.DEC)
pgstats.fields.deltachangedtuples = ProtoField.uint64("pgstats.m2.te.deltachangedtuples", "Delta Changed Tuples", base.DEC)
pgstats.fields.blocksfetched      = ProtoField.uint64("pgstats.m2.te.blocksfetched", "Blocks Fetched", base.DEC)
pgstats.fields.blockshit          = ProtoField.uint64("pgstats.m2.te.blockshit", "Blocks Hit", base.DEC)

-- Message 8 - AUTOVAC_START
pgstats.fields.M8Oid         = ProtoField.uint32("pgstats.m8.oid", "Database ID", base.DEC)
pgstats.fields.M8Oid2        = ProtoField.uint32("pgstats.m8.oid2", "Unknown OID 2", base.DEC) -- Idk what else to call this one
pgstats.fields.M8StartTime   = ProtoField.uint64("pgstats.m8.starttime", "Start Time", base.HEX)

-- Message 12 - BGWriter
pgstats.fields.M12timed_checkpoints       = ProtoField.uint64("pgstats.m12.timed_checkpoints", "Timed Checkpoints", base.DEC)
pgstats.fields.M12requested_checkpoints   = ProtoField.uint64("pgstats.m12.requested_checkpoints", "Requested Checkpoints", base.DEC)
pgstats.fields.M12buf_written_checkpoints = ProtoField.uint64("pgstats.m12.buf_written_checkpoints", "Written Checkpoints", base.DEC)
pgstats.fields.M12buf_written_clean       = ProtoField.uint64("pgstats.m12.buf_written_clean", "Written Clean", base.DEC)
pgstats.fields.M12maxwritten_clean        = ProtoField.uint64("pgstats.m12.maxwritten_clean", "Max Written Clean", base.DEC)
pgstats.fields.M12buf_written_backend     = ProtoField.uint64("pgstats.m12.buf_written_backend", "Written Backend", base.DEC)
pgstats.fields.M12buf_fsync_backend       = ProtoField.uint64("pgstats.m12.buf_fsync_backend", "fsync Backend", base.DEC)
pgstats.fields.M12buf_alloc               = ProtoField.uint64("pgstats.m12.buf_alloc", "Buffer Alloc", base.DEC)
pgstats.fields.M12checkpoint_write_time   = ProtoField.uint64("pgstats.m12.checkpoint_write_time", "Checkpoint Write Time", base.DEC)
pgstats.fields.M12checkpoint_sync_time    = ProtoField.uint64("pgstats.m12.checkpoint_sync_time", "Checkpoint Sync Time", base.DEC)

-- Hot Tipz: Lua Arrays are 1 indexed lol
-- This is for the latest postgres from git
-- local MessageTypesLatest = {
--     "(00) DUMMY",
--     "(01) INQUIRY - Asks collector to write stats file(s)",
--     "(02) TABSTAT - Sent by the backend to report table and buffer access statistics.",
--     "(03) TABPURGE",
--     "(04) DROPDB - Sent by the backend to tell the collector about a dropped database",
--     "(05) RESETCOUNTER",
--     "(06) RESETSHAREDCOUNTER",
--     "(07) RESETSINGLECOUNTER",
--     "(08) RESETSLRUCOUNTER - Sent by the backend to tell the collector to reset a SLRU counter",
--     "(09) RESETREPLSLOTCOUNTER",
--     "(10) AUTOVAC_START",
--     "(11) VACUUM",
--     "(12) ANALYZE - Sent by the backend or autovacuum daemon after ANALYZE",
--     "(13) ARCHIVER - Sent by the archiver to update statistics.",
--     "(14) BGWRITER - Sent by the bgwriter to update statistics.",
--     "(15) CHECKPOINTER - Sent by the checkpointer to update statistics.",
--     "(16) WAL - Sent by backends and background processes to update WAL statistics.",
--     "(17) SLRU - Sent by a backend to update SLRU statistics.",
--     "(18) FUNCSTAT",
--     "(19) FUNCPURGE",
--     "(20) RECOVERYCONFLICT - Sent by the backend upon recovery conflict.",
--     "(21) TEMPFILE - Sent by the backend upon creating a temp file.",
--     "(22) DEADLOCK - Sent by the backend to tell the collector about a deadlock that occurred.",
--     "(23) CHECKSUMFAILURE",
--     "(24) REPLSLOT - Sent by a backend or a wal sender to update replication slot statistics.",
--     "(25) CONNECTION"
-- }

--- This MessageTypes list was originally for 10.18, but is compatible with 12.8 too.
-- To update for your version, look at the StatMsgType enum in src/include/pgstat.h in your version.
-- The enum changes across different versions, adding certain message types and moving others around.
-- Very cool!!
local MessageTypes = {
    "(00) DUMMY",
    "(01) INQUIRY - Asks collector to write stats file(s)",
    "(02) TABSTAT - Sent by the backend to report table and buffer access statistics.",
    "(03) TABPURGE - Sent by the backend to tell the collector about dead tables.",
    "(04) DROPDB - Sent by the backend to tell the collector about a dropped database",
    "(05) RESETCOUNTER - Sent by the backend to tell the collector to reset counters",
    "(06) RESETSHAREDCOUNTER - Sent by the backend to tell the collector to reset a shared counter",
    "(07) RESETSINGLECOUNTER - Sent by the backend to tell the collector to reset a single counter",
    "(08) AUTOVAC_START - Sent by the autovacuum daemon to signal that a database is going to be processed",
    "(09) VACUUM - Sent by the backend or autovacuum daemon after VACUUM",
    "(10) ANALYZE - Sent by the backend or autovacuum daemon after ANALYZE",
    "(11) ARCHIVER - Sent by the archiver to update statistics.",
    "(12) BGWRITER - Sent by the bgwriter to update statistics.",
    "(13) FUNCSTAT - Sent by the backend to report function usage statistics.",
    "(14) FUNCPURGE - Sent by the backend to tell the collector about dead functions.",
    "(15) RECOVERYCONFLICT - Sent by the backend upon recovery conflict.",
    "(16) TEMPFILE - Sent by the backend upon creating a temp file.",
    "(17) DEADLOCK - Sent by the backend to tell the collector about a deadlock that occurred.",
    "(18) CHECKSUMFAILURE - (version 12.8) Sent by the backend to tell the collector about checksum failures noticed."
}

-- Main dissector function
function pgstats.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "Postgres Stats"
    local subtree = tree:add(pgstats, buffer(), "Postgres Stats Data")
	local buff_len = buffer:len()
	local messageType = buffer(0, 4):le_uint()
	local messageTypeName = ""
    local buffptr = 0 -- This is a generic variable for tracking the buffer pointer
	if messageType + 1 > #MessageTypes + 1 then -- Checking if it's greater than the length of the message types array, lua sux
		messageTypeName = "Illegal Value"
	else
		messageTypeName = MessageTypes[messageType+1]
	end
    subtree:add(pgstats.fields.MessageType, messageType, "Message Type: " .. messageTypeName) -- The +1 is because Lua arrays are 1 indexed...
	subtree:add_le(pgstats.fields.MessageLen, buffer(4, 4))

	-- After here should be custom logic for handling each unique message type.
	if messageType == 1 then -- This is a message type 1 - Inquiry
		subtree:add_le(pgstats.fields.M1ClockTime, buffer(8, 8))
		subtree:add_le(pgstats.fields.M1CutoffTime, buffer(16, 8))
		subtree:add_le(pgstats.fields.M1Oid, buffer(24, 4))
	end
    if messageType == 2 then
        local numEntries = buffer(12, 4):le_uint()
        subtree:add_le(pgstats.fields.M2Oid         , buffer(8, 4))
        subtree:add_le(pgstats.fields.M2NumEntries  , buffer(12, 4))
        subtree:add_le(pgstats.fields.M2xactcommit  , buffer(16, 4))
        subtree:add_le(pgstats.fields.M2xactrollback, buffer(20, 4))
        subtree:add_le(pgstats.fields.M2blkreadtime , buffer(24, 8))
        subtree:add_le(pgstats.fields.M2blkwritetime, buffer(32, 8))
        buffptr = 40 -- This is where we are at before we iterate over table entries
        local entryCounter = 0
        while (buffptr < buff_len) do
            entryCounter = entryCounter + 1
            local tableEntrySub = subtree:add(pgstats, buffer(buffptr, 112), "Table Entry "..entryCounter) -- 112 is the length of a table entry
            tableEntrySub:add_le(pgstats.fields.M2teOID           , buffer(buffptr,     4))
            tableEntrySub:add_le(pgstats.fields.M2teUNK1          , buffer(buffptr+4,   4))
            tableEntrySub:add_le(pgstats.fields.numscans          , buffer(buffptr+8,   8))
            tableEntrySub:add_le(pgstats.fields.tuplesreturned    , buffer(buffptr+16,  8))
            tableEntrySub:add_le(pgstats.fields.tuplesfetched     , buffer(buffptr+24,  8))
            tableEntrySub:add_le(pgstats.fields.tuplesinserted    , buffer(buffptr+32,  8))
            tableEntrySub:add_le(pgstats.fields.tuplesupdated     , buffer(buffptr+40,  8))
            tableEntrySub:add_le(pgstats.fields.tuplesdeleted     , buffer(buffptr+48,  8))
            tableEntrySub:add_le(pgstats.fields.tupleshotupdated  , buffer(buffptr+56,  8))
            tableEntrySub:add_le(pgstats.fields.truncated         , buffer(buffptr+64,  8))
            tableEntrySub:add_le(pgstats.fields.deltalivetuples   , buffer(buffptr+72,  8))
            tableEntrySub:add_le(pgstats.fields.deltadeadtuples   , buffer(buffptr+80,  8))
            tableEntrySub:add_le(pgstats.fields.deltachangedtuples, buffer(buffptr+88,  8))
            tableEntrySub:add_le(pgstats.fields.blocksfetched     , buffer(buffptr+96,  8))
            tableEntrySub:add_le(pgstats.fields.blockshit         , buffer(buffptr+104, 8))
            buffptr = buffptr + 112
        end
    end
    if messageType == 8 then
        subtree:add_le(pgstats.fields.M8Oid      , buffer(8, 4))
        subtree:add_le(pgstats.fields.M8Oid2     , buffer(12, 4))
        subtree:add_le(pgstats.fields.M8StartTime, buffer(16, 8))
    end
    if messageType == 12 then
        subtree:add_le(pgstats.fields.M12timed_checkpoints       , buffer(8, 8))
        subtree:add_le(pgstats.fields.M12requested_checkpoints   , buffer(16, 8))
        subtree:add_le(pgstats.fields.M12buf_written_checkpoints , buffer(24, 8))
        subtree:add_le(pgstats.fields.M12buf_written_clean       , buffer(32, 8))
        subtree:add_le(pgstats.fields.M12maxwritten_clean        , buffer(40, 8))
        subtree:add_le(pgstats.fields.M12buf_written_backend     , buffer(48, 8))
        subtree:add_le(pgstats.fields.M12buf_fsync_backend       , buffer(56, 8))
        subtree:add_le(pgstats.fields.M12buf_alloc               , buffer(64, 8))
        subtree:add_le(pgstats.fields.M12checkpoint_write_time   , buffer(72, 8))
        subtree:add_le(pgstats.fields.M12checkpoint_sync_time    , buffer(80, 8))
    end
end

-- This is how we tell Wireshark to use the dissector
udp_table = DissectorTable.get("udp.port")
udp_table:add(48264,pgstats) -- The port will be different every time postgres runs, make sure you update it.

