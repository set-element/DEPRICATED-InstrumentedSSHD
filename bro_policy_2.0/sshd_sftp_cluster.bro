# 01/05/2009: Scott Campbell
#
# sshd_sftp.bro takes sftp related events from the instrumented sshd and
#  creates a summary of users activity.  This is an add on to the sshd_analyzer
#  code and can not be run independantly.
#
#

@load sshd_analyzer_cluster
@load sshd_sftp3_cluster

event sftp_process_close(ts:time, sid:string, cid:count, id: int, handle:int)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_CLOSE_ID";
	t_Info$data = fmt("%s handle: %s", id, handle);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::delete_irecord(CR);
	}
	
event sftp_process_do_stat(ts:time, sid:string, version: string, cid:count, data:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_DO_STAT";
	t_Info$data = fmt("%s", data);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_fsetstat(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_FSETSTAT";
	t_Info$data = fmt("%s", data);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_fstat(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_FSTAT";
	t_Info$data = fmt("%s", data);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_init(ts:time, sid:string, version:string, serv_interfaces:string, cid:count, uid:string, a:addr)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_INIT";
	t_Info$data = fmt("[2] %s %s", uid, a);
	t_Info$uid = uid;

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_mkdir(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_MKDIR";
	t_Info$data = fmt("%s", data);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_open(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_OPEN";
	t_Info$data = fmt("%s", data);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_opendir(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_OPENDIR";
	t_Info$data = fmt("%s", data);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_readdir(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_READDIR";
	t_Info$data = fmt("%s", data);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_readlink(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_READLINK";
	t_Info$data = fmt("%s", data);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_realpath(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_REALPATH";
	t_Info$data = fmt("%s", data);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_remove(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_REMOVE";
	t_Info$data = fmt("%s", data);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_rename(ts:time, sid:string, cid:count, old_name:string, new_name:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_RENAME";
	t_Info$data = fmt("%s %s", old_name, new_name);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_rmdir(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_RMDIR";
	t_Info$data = fmt("%s", data);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_setstat(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_SETSTATS";
	t_Info$data = fmt("%s", data);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_symlink(ts:time, sid:string, cid:count, old_path:string, new_path:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_SYMLINK";
	t_Info$data = fmt("%s %s", old_path, new_path);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
event sftp_process_unknown(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local t_Info = SFTP_AUDIT::get_irecord(CR);

	t_Info$ts = ts;
	t_Info$name = "SFTP_PROCESS_UNKNOWN";
	t_Info$data = fmt("%s", data);

	SFTP_AUDIT::print_sftp_record(t_Info);
	SFTP_AUDIT::update_irecord(CR, t_Info);
	}
	
