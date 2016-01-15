# 12/08/2011: Scott Campbell
#
# Test replacement of tracking login history for a given uid.
#   Store state in serialized form.
#
# Might be better as a extension of the auth module, but for now
#  make it independant, driven by the auth_info event.
#
# Still print to the ssh_auth log for sanities sake 
#
# This is still in alpha format...

module SSHD_AUTH_HIST;

export {

	redef enum Notice += {
		SSHD_AUTHNewSub,
		SSHD_AUTHWinExpire,
		SSHD_AUTHNewKey,
		SSHD_AUTHUidKeyCollision,
		SSHD_AUTHUidPasswdCollision,
	};

	######################################################################################
	#  data structs and tables
	######################################################################################

	type hist_rec: record {
		sn: table[subnet] of count;	# table of successful login nets
		init_time: double;		# time that record was initialized
		ad: set[addr];			# set of addresses that have been logged in from
		accept_time: double;		# last successful login
		fail_time: double;		# last failed login;
		logins: count;			# total accept logins
		pubkey: string;			# public key (if any) used for authentication
		passwd: string;			# password (if any) used for authentication
		};

	# table to hold hist records: make it &persistent since we
	#  are looking at long term historical data
	global lookup_hist: table[string] of hist_rec &persistent;

	# track key -> uid mapping.  if there is an additional account using
	#  the same key, set a notice
	global keymap: table[string] of string &persistent;

	# track password -> uid mapping.  flag collisions for successful logins.
	global passwdmap: table[string] of string &persistent;

	######################################################################################
	#  configuration
	######################################################################################

	# fail window: if time since last login -> fail/success exceeds
	#  window, set a notice.
	global fail_window: interval = 180 days &redef;	
	global accept_window: interval = 180 days &redef;	

	# set a start threshold to begin new subnet notices
	global login_threshold: count = 10 &redef;

	# null address value - default for records wo/ useful data
	global null_address: addr = 0.0.0.0 &redef;

} # end of export

function get24(a: addr) : subnet
{
	# take an address and return an a/24 subnet
	# for now requires a spesific bif - can we work around this?

	return net_to_subnet24(a);
} 

function add_record(uid: string, a: addr) : count
{
	# add a new record, or return 0 for fail
	local ret: count = 0;

	if ( uid !in lookup_hist ) {

		local t_hr: hist_rec;
		local tsc: table[subnet] of count;
		local tsa: set[addr];

		t_hr$accept_time = time_to_double(network_time());
		t_hr$fail_time = time_to_double(network_time());
		t_hr$sn = tsc;
		t_hr$ad = tsa;
		t_hr$logins = 1;
		t_hr$pubkey = "NONE-INIT";

		local tsub: subnet = get24(a);
		t_hr$sn[tsub] = 1;
		add t_hr$ad[a];

		lookup_hist[uid] = t_hr;

		ret = 1;

		}

	return ret;
}

function test_login(uid: string, a: addr): count
{
	# return code values
	# 0 : historical address
	# 1 : new address
	# 2 : new subnet

	local t_hr: hist_rec;
	local ret = 0;

	# punt on null address
	#if ( a == null_address ) 
	#	return ret;

	if ( uid !in lookup_hist )
		add_record(uid,a);

	t_hr = lookup_hist[uid];

	local tsub = get24(a);

	if ( a !in t_hr$ad ) {

		# this is a login from a new address
		# is it from a new subnet?
	
		if ( tsub !in t_hr$sn ) {

			# new address and new subnet: SSHD_AUTHNewSub	
			#  add subnet and mark as new
			add t_hr$ad[a];
			t_hr$sn[tsub] = 1;	

			if ( t_hr$logins >= login_threshold ) 
				ret = 2;
			}
		else {
			# new addr, old subnet.  add address and calculate the
			#  likelyhood of the subnet login
			add t_hr$ad[a];

			# this is a historical retrospective, so look at the 
			#  data before the current address is added
			#	= t_hr$sn[tsub]/t_hr$logins;
			++t_hr$sn[tsub];
			ret = 1;
			}
		}

	# maintenance for all successful logins
	t_hr$accept_time = time_to_double(network_time());
	++t_hr$logins;

	# reset table values
	lookup_hist[uid] = t_hr;


	return ret;
}




event auth_info_3(ts: time, version: string, sid: string, cid: count, authmsg: string, uid: string, meth: string, s_addr: addr, s_port: port, r_addr: addr, r_port: port)
{

	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local SR: SSHD_CORE::server_record = SSHD_CORE::test_sid(sid);
	local t_hr: hist_rec;

	local tsub = get24(s_addr);

	# this is duplicated in test_login() but the test is cheap and will
	#  avoid corner cases 
	if ( uid !in lookup_hist )
		add_record(uid, s_addr);

	t_hr = lookup_hist[uid];


	if ( to_upper(authmsg) == "ACCEPTED" ) {

		# test for excessive time since last login
		local window = double_to_interval( time_to_double(network_time()) - t_hr$accept_time );
		if ( window > accept_window ) {

			NOTICE([$note=SSHD_AUTHWinExpire,
				$msg=fmt("Excessive login window for %s %s %s", uid, CR$client_tag, window)]);
			
			print SSHD_AUTH::sshd_auth_log, fmt("%.6f #%s - %s %s AUTH Excessive time window %s",
				ts, CR$client_tag, SSHD_CORE::print_sid(sid), cid, window);
			}

		# run the login
		local n = test_login(uid,s_addr);

		if ( n == 1 ) {
			# new address
			local ps: double =  t_hr$sn[tsub]/t_hr$logins;

			print SSHD_AUTH::sshd_auth_log, fmt("%.6f #%s - %s %s AUTH NEW-ADDRESS %s %d",
				ts, CR$client_tag, SSHD_CORE::print_sid(sid), cid, s_addr, ps);
	
			}
		else if ( n == 2 ) {
			# new subnet
			NOTICE([$note=SSHD_AUTHNewSub,
				$msg=fmt("New subnet for %s %s %s %s", uid, s_addr, tsub, t_hr$logins)]);
			
			print SSHD_AUTH::sshd_auth_log, fmt("%.6f #%s - %s %s AUTH NEW-SUBNET %s",
				ts, CR$client_tag, SSHD_CORE::print_sid(sid), cid, get24(s_addr));
			}

	}

} 

event auth_key_fingerprint_3(ts: time, version: string, sid: string, cid: count, fingerprint: string, key_type: string)
{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	if ( strcmp(CR$uid,"UNKNOWN") == 0 )
		return;

	# this is duplicated in test_login() but the test is cheap and will
	#  avoid corner cases 
	if ( CR$uid !in lookup_hist )
		add_record(CR$uid, CR$conn$id$orig_h);

	#local t_hr = lookup_hist[CR$uid];

	if ( strcmp(lookup_hist[CR$uid]$pubkey, "NONE-INIT") == 0 ) {
		
			NOTICE([$note=SSHD_AUTHNewKey,
				$msg=fmt("New key for #%s %s %s -> %s", 
					CR$client_tag, CR$uid, lookup_hist[CR$uid]$pubkey, fingerprint)]);
		
			print SSHD_CORE::sshd_log, fmt("%.6f #%s - %s %s AUTH_KEY_NEW_FINGERPRINT %s type %s", 
				ts, CR$client_tag, SSHD_CORE::print_sid(sid), cid, fingerprint, key_type);

			lookup_hist[CR$uid]$pubkey = fingerprint;	
		}

	# test mapping between key and uid
	if ( fingerprint in keymap ) {

		local tuid = keymap[fingerprint];

		if ( strcmp(tuid,CR$uid) != 0 ) {
			
			# change in mapping
			NOTICE([$note=SSHD_AUTHUidKeyCollision,
				$msg=fmt("Key in #%s %s {%s,%s}", 
					CR$client_tag, fingerprint, tuid, CR$uid)]);
			}
		}
	else {
		# add the mapping pair
		keymap[fingerprint] = CR$uid;

		}

}


event auth_pass_attempt_3(ts: time, version: string, sid: string, cid: count, authenticated: count, uid: string, password: string)
{
	# starting in version 3.05 a sha1 hash of the password will be passed
	#  to this event if --with-passrec is *not* used.  This will allow
	#  for the identification of dictionary attacks, shared passwords etc
	#  without having to move the volitile data around.
	#
	# 	global passwdmap: table[string] of string &persistent;

	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	# only interested in looking at authenticated = T values since otherwise
	#  it would be an overwhelming mess of noise.

	if ( authenticated == 1 ) {
		
		if ( password in passwdmap ) {
		
			# make sure that nothing has changed SSHD_AUTHUidPasswdCollision	
			local tuid = passwdmap[password];

			if ( strcmp(tuid,CR$uid) != 0 ) {
			
				# change in mapping
				NOTICE([$note=SSHD_AUTHUidPasswdCollision,
					$msg=fmt("password in #%s {%s,%s}", 
						CR$client_tag, uid, CR$uid)]);
				}

			}
		else {
			passwdmap[password] = uid;

			}

		}
}


