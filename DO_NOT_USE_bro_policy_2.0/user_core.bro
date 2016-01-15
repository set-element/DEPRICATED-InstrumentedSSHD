# 03/28/2011: Scott Campbell
#
# This defines a set of functions and tables which will knit together authentication information
#  from the sshd and syslog policy.
#
# 
#@load sql

module USER_CORE;

export {

	redef enum Notice::Type += {
		USER_AuthFail,			#
		SensitiveRemoteLogin,		#
		USER_AUTH_FailTot,		#
		USER_AUTH_UidFail,		#
		USER_AUTH_NumAcct,		#

		USER_AUTHNewSub,		# New subnet for uid
		USER_AUTHNewKey,		# Key replacement for uid
		USER_AUTHUidKeyCollision,	# two accounts have the same public key
		USER_AUTHUidPasswdCollision,	# two accounts have the same password
	};

	## The USER_CORE logging stream identifier	
	redef enum Log::ID += { LOG };

        ######################################################################################
        #  DATA STRUCTS AND TABLES
        ######################################################################################

	# record used to log transactions related to A&A
	type Info: record {
		## Record for user transaction
		ts:		time &log;
		key:		string &log &default="NA";
		id:		conn_id &log;
		host:		string &log &default="UNKNOWN_HOST";
		uid:		string &log &default="UNKNOWN_UID";
		# service name: ssh, https, ldap etc
		svc_name:	string &log &default="UNKNOWN_SVC";
		# service type: authentication, authorization etc
		svc_type:	string &log &default="UNKNOWN_TYPE";
		# service response
		svc_resp:	string &log &default="UNKNOWN_RESP";
		# service auth: type of authentiation used in transaction
		svc_auth:	string &log &default="UNKNOWN_AUTH";
		# transaction data
		data:		string &log;
		};

	# record used to track *address* behavior, orthoginal to uid behavior
	type addr_rec: record {
		fail_uid: table[string] of count;	# list of uid:count fail pairs
		accept_uid: set[string];		# list of uid accepts
		total_login_fail: count;		# total failed logins per s_addr
		total_login_accept: count;		# total accept per s_addr
		total_host_fail: count;			# total unique local hosts
		dest_a: table[addr] of count;		# list of host:count fail pairs
		};

	# record to track *uid* behavior 
	type uid_rec: record {
		from_net: table[subnet] of count;
		total: count &default=0;
		};

	# data table for address behavior
	global login_data: table[addr] of addr_rec &persistent;
	# data table for uid behavior
	global uid_data: table[string] of uid_rec &persistent;

	## Identifying maps between uid and authentication token requires a 
	#   successful login for the information to be useful.  This is a table
	#   to hold all authentication data for a short period of time.
	#  Map of session-key -> fingerprint
	global uid_cred_cache: table[string] of string &write_expire=1 min &redef;
	#  perminant uid <-> fingerprint set
	global uid_lookup: table[string] of string &persistent;

	# do we log via sqlite?
	const log_sqlite = F &redef;
	
	#
        ######################################################################################
        # GLOBAL FUNCTIONS
        ######################################################################################
	
	# general interface is the auth_transaction() event which drives the following functions:

	global user_accept: function(ts: time, s_addr: addr, r_addr: addr, uid: string, data_src: string, key: string);
	global user_fail: function(ts: time, s_addr: addr, r_addr: addr, uid: string, data_src: string, key: string);
	global user_postponed: function(ts: time, s_addr: addr, r_addr: addr, uid: string, data_src: string, key: string);
	global user_invalid: function(s_addr: addr, r_addr: addr, uid: string);

	global user_history: function(ts: time, id: conn_id, uid: string, svc_name: string, svc_type: string, svc_resp: string, svc_auth: string, data: string): count;

	global auth_key_fingerprint_3: event(ts: time, version: string, sid: string, cid: count, fingerprint: string, key_type: string);
	global auth_transaction: event(ts: time, key: string, id: conn_id, uid: string, host: string, svc_name: string, svc_type: string, svc_resp: string, svc_auth: string, data: string);
	global auth_transaction_token: event(uid: string, session_key: string, data: string);
        ######################################################################################
        # CONFIGURATION
        ######################################################################################

	# number of individual hosts the s_addr can fail
	global sshd_r_addr_thresh: count = 20 &redef;
	# number of fails per account
	global sshd_per_account: count = 10 &redef;
	# total fails per s_addr across all addresses and accounts
	global sshd_fail_total: count = 20 &redef;
	# total number of failed accounts
	global sshd_num_fail_accts: count = 10 &redef;

	const suspicious_accounts = { "lp", "toor", "admin", "test", "r00t", "bash", } &redef;
	const remote_accounts = { "root", "system", "operator","lp", "toor", "admin", "test", "r00t", "bash", "guest", "user", } &redef;
		
	const skip_login_dest = { 128.55.15.11, } &redef;
	const host_whitelist = { 128.55.16.16, } &redef;
	const net_whitelist = { 128.55.0.0/16, } &redef;

	# how many logins must be seen before a uid is checked against it's history?
	const uid_login_threshold: count = 10 &redef;
	# subnet mask to apply to addresses - expressed as bitmask
	const bitmap_box = 24 &redef;
	# ignore local addresses for history?
	const skip_local_addr_history = T &redef;

} # end of export

######################################################################################
##  functions 
#######################################################################################

function test_addr(a: addr) : addr_rec
{
	# return a set up addr_rec
	local t_AR: addr_rec;
	local t_fud: table[string] of count;
	local t_uid: set[string];
	local t_dest: table[addr] of count;

	if ( a !in login_data ) {

		t_AR$fail_uid = t_fud;
		t_AR$accept_uid = t_uid;
		t_AR$total_login_fail = 0;
		t_AR$total_login_accept = 0;
		t_AR$total_host_fail = 0;
		t_AR$dest_a = t_dest;

		login_data[a] = t_AR;
		}
	else
		t_AR = login_data[a];

	return t_AR;
}

function test_uid(uid: string): uid_rec
{
	local t_UR: uid_rec;

	if ( uid in uid_data )
		t_UR = uid_data[uid];
	else {
		# this is a new record so build data structs and set any values needed
		local t_sub: table[subnet] of count;

		t_UR$from_net = t_sub;
		}

	return t_UR;
}

function create_conn_id(s_addr: addr, s_port: port, r_addr: addr, r_port: port) : conn_id
{
	local id: conn_id;

	id$orig_h = s_addr;
	id$orig_p = s_port;
	id$resp_h = r_addr;
	id$resp_p = r_port;

	return id;
}

function log_transaction(ts: time, key: string, id: conn_id, uid: string, host: string, svc_name: string, svc_type: string, svc_resp: string, svc_auth: string, data: string) : count
{
	local t_Info: Info;
	local ret: count = 0;

	t_Info$ts = ts;
	t_Info$key = key;
	t_Info$id = id;
	t_Info$uid = uid;
	t_Info$host = host;
	t_Info$svc_name = svc_name;
	t_Info$svc_type = svc_type;
	t_Info$svc_resp = svc_resp;
	t_Info$svc_auth = svc_auth;
	t_Info$data = data;

	# and print the results
	Log::write(LOG, t_Info);

	return ret;
}

function user_history(ts: time, id: conn_id, uid: string, svc_name: string, svc_type: string, svc_resp: string, svc_auth: string, data: string) : count
{
	## For the transaction line provided, test user history etc
	local ret_val: count = 0;
	local t_UR = test_uid(uid);
	local t_net = mask_addr(id$orig_h, bitmap_box);

	# do we punt on local addresses?
	if ( skip_local_addr_history ) {
		if ( Site::is_local_addr(id$orig_h) )
			return ret_val;
		}

	# see if this network has been observed already for the uid
	if ( t_net in t_UR$from_net ) {
		# already seen, add the data and move on ...
		++t_UR$from_net[t_net];
		++t_UR$total;
		#print fmt("UID: %s seen from net %s already %s times", uid,t_net,t_UR$total);
		}
	else {
		# the net not observed before for this uid
		#   and the total number of observations is
		#   under the uid_login_threshold for the uid
		#
		if ( t_UR$total < uid_login_threshold ) {
			t_UR$from_net[t_net] = 1;
			++t_UR$total;
			#print fmt("UID: %s new net %s", uid,t_net);
 			}
		else {
		# new data value, worth evaluating?  move this over to the user_policy.bro
		#   when it is created.
		# for now, apply the following rule: given 'n' data points in 'b' bins
		#   if ( n > T1 ) and ( b < T2 ) out of box logins are rare.
		#   if ( n > T1 )                general logging scenerio...
		#
			local n = t_UR$total;		# number data points
			local b = |t_UR$from_net|;	# number of buckets
		# come back to this ...

			NOTICE([$note=USER_AUTHNewSub,
				$msg=fmt("new subnet %s for %s [%s]", uid, t_net, b)]);
			
			t_UR$from_net[t_net] = 1;
			++t_UR$total;

			#print fmt("new subnet %s for %s [%s]", uid, t_net, b);
		}
	}

	uid_data[uid] = t_UR;

	return ret_val;
}

function user_accept(ts: time, s_addr: addr, r_addr: addr, uid: string, data_src: string, key: string)
{
	# General successful authentication function
	#
	# additional fields:
	#  data_src: {sshd|syslog|...}
	#  aux: optional identifying value ex sshd session identifier
	#
	local t_AR: addr_rec;

	t_AR = test_addr(s_addr);

	if ( uid in remote_accounts && !Site::is_local_addr(s_addr) ) {
		# This account should never be seen to log in successfully
		#  from off site.  Depending on how the NOTICE is handeled, 
		#  we may alarm, drop etc based on local policy.
		NOTICE([$note=SensitiveRemoteLogin,
			$msg=fmt("%s -> %s@%s successful sensitive remote login",
				s_addr, uid, r_addr)]);
		}	

	++t_AR$total_login_accept;

	if ( uid !in t_AR$accept_uid )
		add t_AR$accept_uid[uid];

	if ( r_addr !in t_AR$dest_a )
		t_AR$dest_a[r_addr] = 0;

	++t_AR$dest_a[r_addr];

	# save value
	login_data[s_addr] = t_AR;

	# now do a quick check to see if there are collisions in the auth token...
	if ( key in uid_cred_cache ) {

		# get fingerprint
		local t_key = uid_cred_cache[key];
		local t_uid: string;

		# now get cached uid
		if ( t_key in uid_lookup ) {
			t_uid = uid_lookup[t_key];	

			if ( t_uid != uid ) {

				# two uid's with the same key ...
				NOTICE([$note=USER_AUTHUidKeyCollision,
					$msg=fmt("uid %s and %s share key %s", t_uid, uid, t_key)]);
				}
			}
		else {
			uid_lookup[t_key] = uid;
			}
		}

	#if ( log_sqlite)
		#event SQLITE::auth_logger(uid, mask_addr(s_addr, bitmap_box), data_src);

	return;
}

function user_fail(ts: time, s_addr: addr, r_addr: addr, uid: string, data_src: string, key: string)
{
	# General failed authentication function
	local t_AR: addr_rec;

	t_AR = test_addr(s_addr);

	## start incrementing and testing against thresholds

	# sshd_fail_total: total number of failes per source ip
	if ( ++t_AR$total_login_fail == sshd_fail_total ) {
		
		NOTICE([$note=USER_AUTH_FailTot,
			$msg=fmt("host %s failed %s total logins", s_addr, sshd_fail_total)]);
	}

	if ( uid !in t_AR$fail_uid ){
		t_AR$fail_uid[uid] = 0;
		}

	# total number of fails per account	
	if ( ++t_AR$fail_uid[uid] == sshd_per_account ) {

		NOTICE([$note=USER_AUTH_UidFail,
			$msg=fmt("host %s failed %s total logins for %s", 
				s_addr, sshd_per_account, uid)]);
	}

	# total number of failed accounts
	if ( |t_AR$fail_uid| == sshd_num_fail_accts ) {

		# create a list of accounts
		local t_uid: string = " ";
		local s: string;

		for (s in t_AR$fail_uid) {
			t_uid = fmt("%s %s", t_uid, s);
			}

		NOTICE([$note=USER_AUTH_NumAcct,
			$msg=fmt("host %s failed %s accounts: {%s }",
				s_addr, sshd_num_fail_accts, t_uid)]);
	}

	# total number of failed login dest hosts
	#if ( t_AR$total_host_fail

	#total num of fails per dest address

}

function user_postponed(ts: time, s_addr: addr, r_addr: addr, uid: string, data_src: string, key: string)
{
	#

}

## This is the main gateway as an authentication abstraction
#
# service name (ssh, http, nim etc)
# service type (authentication, authorization etc etc)
# service response ('ACCEPTED', 'FAILED' and 'POSTPONED') (prev called authmsg)
#  the set can be extended via the usual event hyjinx...
#
event auth_transaction(ts: time, key: string, id: conn_id, uid: string, host: string, svc_name: string, svc_type: string, svc_resp: string, svc_auth: string, data: string)
{
	# first normalize all the non-case sensitive informaiton
	local t_svc_name = to_upper(svc_name);
	local t_svc_type = to_upper(svc_type);
	local t_svc_resp = to_upper(svc_resp);
	local t_svc_auth = to_upper(svc_auth);

	## process the transaction in terms of the source address
	# the auth method will be passed along in the data field
	if ( t_svc_resp == "ACCEPTED" ) {
		# user_accept(ts: time, s_addr: addr, r_addr: addr, uid: string, data_src: string, aux: string, key: string)
		user_accept(ts, id$orig_h, id$resp_h, uid, t_svc_name, data);
	
		## now take care of the user account history
		user_history(ts, id, uid, t_svc_name, t_svc_type, t_svc_resp, t_svc_auth, data);
		}

	if ( t_svc_resp == "FAILED" )
		user_fail(ts, id$orig_h, id$resp_h, uid, t_svc_name, data);

	if ( t_svc_resp == "POSTPONED" )
		user_postponed(ts, id$orig_h, id$resp_h, uid, t_svc_name, data);

	## transactional logging
	log_transaction(ts, key, id, uid, host, t_svc_name, t_svc_type, t_svc_resp, t_svc_auth, data);
}

## This is the gateway for the authentication *token* to identify collisions
#   and re-use.
#  Current set of use cases: AUTH_KEY_FINGERPRINT and AUTH_PASS_ATTEMPT
#  Since passing auth token is decoupled from the response, there has to be a short lived
#    queue of values that is registered when a user is successfully authenticated.  There is
#    probably a better way, but this will do for now ... 
#  To identify the keys, the [session key] is attached to the [authentication key] and moved in the data field
event auth_transaction_token(uid: string, session_key: string, data: string)
{
	# set the cache table value	
	uid_cred_cache[session_key] = data;
}

event bro_init() &priority=5
{
	Log::create_stream(USER_CORE::LOG, [$columns=Info]);
}
