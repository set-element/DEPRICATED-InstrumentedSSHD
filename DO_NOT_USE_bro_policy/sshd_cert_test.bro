# 01/06/2009: Scott Campbell
#
# sshd_cert_test.bro compares the fingerprint of the public key used for
#  authentication and compares it to a list of known bad fingerprints.
#
# Some basic utility functions are included as well.
@load sshd_analyzer

redef enum Notice += {
	SSHD_BadKey,
};

redef notice_action_filters += {
	[SSHD_BadKey] = send_email_notice,
};

global bad_key_list: set[string] &redef;

event sshd_key_fingerprint(ts:time, sid:string, cid:count, fingerprint:string, key_type:string)
	{
	local CR:SSHD_ANALYZER::client_record = SSHD_ANALYZER::test_cid(sid,cid);

	if ( fingerprint in bad_key_list ) {
	
		# send up a flag ...
		NOTICE([$note=SSHD_BadKey,
			$msg=fmt("#%s 0 %s %s %s @ %s -> %s:%s %s %s %s",
			CR$client_tag, sid, cid, CR$uid,
			CR$conn$id$orig_h, sid, CR$conn$id$resp_h,
			CR$conn$id$resp_p, key_type, fingerprint)]);
			
		print SSHD_ANALYZER::sshd_log, fmt("%.6f #%s - %s %s ssh_known_bad_key %s type %s", ts, CR$client_tag, sid, cid, fingerprint, key_type);
		}
		
	}
	
event sshd_key_add_hostile(key:string)
	{
	
	if ( key !in bad_key_list ) {
	
		add bad_key_list[key];
		}
		
	}
	
event sshd_key_remove_hostile(key:string)
	{
	
	if ( key in bad_key_list ) {
	
		delete bad_key_list[key];
		}
		
	}
