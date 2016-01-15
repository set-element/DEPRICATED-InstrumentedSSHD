# 03/25/2011: Scott Campbell
#
# sshd_sftp.bro takes sftp related events from the instrumented sshd and
#  creates a summary of users activity.  This is an add on to the sshd_analyzer
#  code and can not be run independantly.
#
#

@load sshd_core
module SFTP_AUDIT;

export {
	global SFTP_POLICY_LOADED: bool = T;
	}

event sftp_process_close_3(ts:time, version: string, sid:string, cid:count, ppid: int, id: int, handle:int)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_CLOSE_ID: %s handle: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, id, handle);
	}
	
event sftp_process_do_stat_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_DO_STAT name:  %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, data);
	}
	
event sftp_process_fsetstat_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_FSETSTAT handle to name: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, data);
	}
	
event sftp_process_fstat_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_FSTAT handle to name: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, data);
	}
	
event sftp_process_init_3(ts:time, version: string, sid:string, cid:count, ppid: int, vsn: string, caddr: addr)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_INIT version: %s %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, vsn, caddr);
	}
	
event sftp_process_mkdir_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_MKDIR name: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, data);
	}
	
event sftp_process_open_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{

	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_OPEN name: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, data);
	}
	
event sftp_process_opendir_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_OPENDIR name: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, data);
	}
	
event sftp_process_readdir_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_READDIR name: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, data);
	}
	
event sftp_process_readlink_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_READLINK path: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, data);
	}
	
event sftp_process_realpath_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_REALPATH path: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, data);
	}
	
event sftp_process_remove_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_REMOVE name: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, data);
	}
	
event sftp_process_rename_3(ts:time, version: string, sid:string, cid:count, ppid: int, old_name:string, new_name:string)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_RENAME old_name: %s new_name: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, old_name, new_name);
	}
	
event sftp_process_rmdir_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_RMDIR name: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, data);
	}
	
event sftp_process_setstat_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_SETSTAT name: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, data);
	}
	
event sftp_process_symlink_3(ts:time, version: string, sid:string, cid:count, ppid: int, old_path:string, new_path:string)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_SYMLINK old_path: %s new_path: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, old_path, new_path);
	}
	
event sftp_process_unknown_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	{
	cid = SSHD_CORE::lookup_cid(sid,ppid);
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s SFTP_PROCESS_UNKNOWN type: %s", ts, CR$client_tag,SSHD_CORE::print_sid(sid),cid, data);
	}
	
	
