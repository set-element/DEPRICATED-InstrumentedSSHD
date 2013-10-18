# 03/25/2011: Scott Campbell
#
# sshd_sftp.bro takes sftp related events from the instrumented sshd and
#  creates a summary of users activity.  This is an add on to the sshd_analyzer
#  code and can not be run independantly.
#
# For cluster format the logging specific to sftp will get broken out into it's own logging
#   table to reduce "clutter" for the basic ssh logging.

@load sshd_core_cluster
module SFTP_AUDIT;

export {
	global SFTP_POLICY_LOADED: bool = T;

	# The SFTP_AUDIT logging stream identifier
	redef enum Log::ID += { LOG };

	## Record type which contains column fields for the isshd log
	type Info: record {

		## timestamp
		ts:		time	&log;
		## key for session identification
		key:		string	&log;
		## user assosciated with session
		uid:		string	&log;
		## server host name
		#host:           string  &log &default="HOST_UNKNOWN";
		## event name
		name:           string  &log &default="EVENT_UNKNOWN";
		## event data
		data:           string  &log &default="DATA_UNKNOWN";
		};

	global print_sftp_record: function(i: Info) : count;
	# record manipulation functions
	global get_irecord: function(CR: SSHD_CORE::client_record) : Info;
	global delete_irecord: function(CR: SSHD_CORE::client_record) : count;
	global update_irecord: function(CR: SSHD_CORE::client_record, REC: Info) : count;

	# A place for the session data records to live
	global irecord_box: table[string] of Info;
	}


function print_sftp_record(i: Info) : count
	{
	# print SFTP record and get on with our lives ...
	Log::write(LOG, i);
	return 0;
	}

function get_irecord(CR: SSHD_CORE::client_record) : Info
	{
	local t_Info: Info;

	if ( CR$log_id in irecord_box )
		t_Info = irecord_box[CR$log_id];
	else {
		t_Info$key = CR$log_id;
		t_Info$uid = CR$uid;

		irecord_box[CR$log_id] = t_Info;
		}

	return t_Info;
	}

function delete_irecord(CR: SSHD_CORE::client_record) : count
	{
	local ret: count = 0;

	if ( CR$log_id in irecord_box ) {
		delete irecord_box[CR$log_id];
		ret = 1;
		}

	return ret;
	}

function update_irecord(CR: SSHD_CORE::client_record, REC: Info) : count
	{
	local ret: count = 0;

	if ( CR$log_id in irecord_box ) {
		irecord_box[CR$log_id] = REC;
		ret = 1;
		}

	return ret;
	}

event sftp_process_close_3(ts:time, version: string, sid:string, cid:count, ppid: int, id: int, handle:int)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_CLOSE_ID";
	t_Info$data = fmt("%s handle: %s", id, handle);
	
	print_sftp_record(t_Info);
	delete_irecord(CR);
	}
	
event sftp_process_do_stat_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_DO_STAT";
	t_Info$data = fmt("%s", data);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_fsetstat_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_FSETSTAT";
	t_Info$data = fmt("%s", data);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_fstat_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_FSTAT";
	t_Info$data = fmt("%s", data);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_init_3(ts:time, version: string, sid:string, cid:count, ppid: int, vsn: string, caddr: addr)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_INIT";
	t_Info$data = fmt("[3] %s %s", vsn, caddr);
	t_Info$uid = CR$uid;
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_mkdir_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_MKDIR";
	t_Info$data = fmt("%s", data);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_open_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{

	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_OPEN";
	t_Info$data = fmt("%s", data);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_opendir_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_OPENDIR";
	t_Info$data = fmt("%s", data);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_readdir_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_READDIR";
	t_Info$data = fmt("%s", data);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_readlink_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_READLINK";
	t_Info$data = fmt("%s", data);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_realpath_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_OPENDIR";
	t_Info$data = fmt("%s", data);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_remove_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_REMOVE";
	t_Info$data = fmt("%s", data);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_rename_3(ts:time, version: string, sid:string, cid:count, ppid: int, old_name:string, new_name:string)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_RENAME";
	t_Info$data = fmt("%s %s", old_name, new_name);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_rmdir_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_RMDIR";
	t_Info$data = fmt("%s", data);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_setstat_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_SETSTAT";
	t_Info$data = fmt("%s", data);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_symlink_3(ts:time, version: string, sid:string, cid:count, ppid: int, old_path:string, new_path:string)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_SYMLINK";
	t_Info$data = fmt("%s %s", old_path, new_path);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}
	
event sftp_process_unknown_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	local n_cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,n_cid);

	local t_Info = get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_UNKNOWN";
	t_Info$data = fmt("%s", data);
	
	print_sftp_record(t_Info);
	update_irecord(CR, t_Info);
	}

event bro_init() &priority=5
{
        Log::create_stream(SFTP_AUDIT::LOG, [$columns=Info]);
}
