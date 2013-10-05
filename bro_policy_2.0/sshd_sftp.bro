# 01/05/2009: Scott Campbell
#
# sshd_sftp.bro takes sftp related events from the instrumented sshd and
#  creates a summary of users activity.  This is an add on to the sshd_analyzer
#  code and can not be run independantly.
#
# This is written for >= bro v. 1.4
#

@load sshd_analyzer

event sftp_process_close(ts:time, sid:string, cid:count, id: int, handle:int)
#event sftp_process_close(ts:time, sid:string, version: string, cid:string, n:count, id: int, handle:int)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_close id: %s handle: %s", ts, CR$client_tag, sid, cid, id, handle);
	}
	
event sftp_process_do_stat(ts:time, sid:string, version: string, cid:count, data:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_do_stat name:  %s", ts, CR$client_tag, sid, cid, data);
	}
	
event sftp_process_fsetstat(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_fsetstat handle to name: %s", ts, CR$client_tag, sid, cid, data);
	}
	
event sftp_process_fstat(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_fstat handle to name: %s", ts, CR$client_tag, sid, cid, data);
	}
	
event sftp_process_init(ts:time, sid:string, version:string, serv_interfaces:string, cid:count, uid:string, a:addr)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_init version: %s %s %s", ts, CR$client_tag, sid, cid, version,uid,a);
	}
	
event sftp_process_mkdir(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_mkdir name: %s", ts, CR$client_tag, sid, cid, data);
	}
	
event sftp_process_open(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_open name: %s", ts, CR$client_tag, sid, cid, data);
	}
	
event sftp_process_opendir(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_opendir name: %s", ts, CR$client_tag, sid, cid, data);
	}
	
event sftp_process_readdir(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_readdir name: %s", ts, CR$client_tag, sid, cid, data);
	}
	
event sftp_process_readlink(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_readlink path: %s", ts, CR$client_tag, sid, cid, data);
	}
	
event sftp_process_realpath(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_realpath path: %s", ts, CR$client_tag, sid, cid, data);
	}
	
event sftp_process_remove(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_remove name: %s", ts, CR$client_tag, sid, cid, data);
	}
	
event sftp_process_rename(ts:time, sid:string, cid:count, old_name:string, new_name:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_rename old_name: %s new_name: %s", ts, CR$client_tag, sid, cid, old_name, new_name);
	}
	
event sftp_process_rmdir(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_rmdir name: %s", ts, CR$client_tag, sid, cid, data);
	}
	
event sftp_process_setstat(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_setstat name: %s", ts, CR$client_tag, sid, cid, data);
	}
	
event sftp_process_symlink(ts:time, sid:string, cid:count, old_path:string, new_path:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_symlink old_path: %s new_path: %s", ts, CR$client_tag, sid, cid, old_path, new_path);
	}
	
event sftp_process_unknown(ts:time, sid:string, cid:count, data:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s sftp_process_unknown type: %s", ts, CR$client_tag, sid, cid, data);
	}
	
	
