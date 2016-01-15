# 03/28/2011: Scott Campbell
#
# This defines a set of functions and tables which will knit together authentication information
#  from the sshd and syslog policy.
#
# 

module SSHD_AUTH;

export {

	redef enum Notice += {
		SSHD_AuthFail,
		SensitiveRemoteLogin,
		SSHD_AUTH_FailTot,
		SSHD_AUTH_UidFail,
		SSHD_AUTH_NumAcct,
	};

	global sshd_auth_log: file = open_log_file("sshd_auth");

	global ssh_accept: function(ts: time, s_addr: addr, r_addr: addr, uid: string, data_src: string, aux: string, meth: string);
	global ssh_fail: function(ts: time, s_addr: addr, r_addr: addr, uid: string, data_src: string, aux: string, meth: string);
	global ssh_postponed: function(ts: time, s_addr: addr, r_addr: addr, uid: string, data_src: string, aux: string, meth: string);
	global ssh_invalid: function(s_addr: addr, r_addr: addr, uid: string);

	type acct_rec: record {
		fail_uid: table[string] of count;	# list of uid:count fail pairs
		accept_uid: set[string];		# list of uid accepts
		total_login_fail: count;		# total failed logins per s_addr
		total_login_accept: count;		# total accept per s_addr
		total_host_fail: count;			# total unique local hosts
		dest_a: table[addr] of count;		# list of host:count fail pairs
	};

	# main data table
	global login_data: table[addr] of acct_rec;

	# number of individual hosts the s_addr can fail
	global sshd_r_addr_thresh: count = 20 &redef;
	# number of fails per account
	global sshd_per_account: count = 10 &redef;
	# total fails per s_addr across all addresses and accounts
	global sshd_fail_total: count = 20 &redef;
	# total number of failed accounts
	global sshd_num_fail_accts: count = 10 &redef;

	const suspicious_accounts = { "lp", "toor", "admin", "test", "r00t", "bash", } &redef;
	const remote_accounts = { "root", "system", "operator","lp", "toor", "admin", "test", "r00t", "bash"
, "guest", "user", } &redef;
		
	const skip_login_dest = { 128.55.15.11, } &redef;
	const host_whitelist = { 128.55.16.16, } &redef;
	const net_whitelist = { 128.55.0.0/16, } &redef;

} # end of export

function init_acct_rec() : acct_rec
{
	# return a set up acct_rec
	local t_ar: acct_rec;
	local t_fud: table[string] of count;
	local t_uid: set[string];
	local t_dest: table[addr] of count;

	t_ar$fail_uid = t_fud;
	t_ar$accept_uid = t_uid;
	t_ar$total_login_fail = 0;
	t_ar$total_login_accept = 0;
	t_ar$total_host_fail = 0;
	t_ar$dest_a = t_dest;

	return t_ar;
}

function ssh_accept(ts: time, s_addr: addr, r_addr: addr, uid: string, data_src: string, aux: string, meth: string)
{
	# General successful authentication function
	#
	# additional fields:
	#  data_src: {sshd|syslog|...}
	#  aux: optional identifying value ex sshd session identifier
	#
	local t_ar: acct_rec;

	if ( s_addr !in login_data ) {
		t_ar = init_acct_rec();
	}
	else
		t_ar = login_data[s_addr];

	if ( uid in remote_accounts && !is_local_addr(s_addr) ) {
		# This account should never be seen to log in successfully
		#  from off site.  Depending on how the NOTICE is handeled, 
		#  we may alarm, drop etc based on local policy.
		NOTICE([$note=SensitiveRemoteLogin,
			$msg=fmt("%s -> %s@%s successful sensitive remote login",
				s_addr, uid, r_addr)]);
	}	

	++t_ar$total_login_accept;

	if ( uid !in t_ar$accept_uid )
		add t_ar$accept_uid[uid];

	if ( r_addr !in t_ar$dest_a )
		t_ar$dest_a[r_addr] = 0;

	++t_ar$dest_a[r_addr];

	# save value
	login_data[s_addr] = t_ar;

	print sshd_auth_log, fmt("%.6f %s %s ACCEPT %s %s @ %s -> %s",
		ts, aux, data_src, meth, uid, s_addr, r_addr);

	return;
}

function ssh_fail(ts: time, s_addr: addr, r_addr: addr, uid: string, data_src: string, aux: string, meth: string)
{
	# General failed authentication function
	local t_ar: acct_rec;

	if ( s_addr !in login_data ) {
		t_ar = init_acct_rec();
	}
	else
		t_ar = login_data[s_addr];

	# start incrementing and testing against thresholds

	# sshd_fail_total: total number of failes per source ip
	if ( ++t_ar$total_login_fail == sshd_fail_total ) {
		
		NOTICE([$note=SSHD_AUTH_FailTot,
			$msg=fmt("host %s failed %s total logins", s_addr, sshd_fail_total)]);
	}

	if ( uid !in t_ar$fail_uid ){
		t_ar$fail_uid[uid] = 0;
		#print fmt("adding %s, %s", uid, |t_ar$fail_uid|);
		}

	# total number of fails per account	
	if ( ++t_ar$fail_uid[uid] == sshd_per_account ) {

		NOTICE([$note=SSHD_AUTH_UidFail,
			$msg=fmt("host %s failed %s total logins for %s", 
				s_addr, sshd_per_account, uid)]);
	}

	# total number of failed accounts
	if ( |t_ar$fail_uid| == sshd_num_fail_accts ) {

		# create a list of accounts
		local t_uid: string = " ";
		local s: string;

		for (s in t_ar$fail_uid) {
			t_uid = fmt("%s %s", t_uid, s);
			}

		NOTICE([$note=SSHD_AUTH_NumAcct,
			$msg=fmt("host %s failed %s accounts: {%s }",
				s_addr, sshd_num_fail_accts, t_uid)]);
	}

	# total number of failed login dest hosts
	#if ( t_ar$total_host_fail

	#total num of fails per dest address

	print sshd_auth_log, fmt("%.6f %s %s FAIL %s %s @ %s -> %s",
		ts, aux, data_src, meth, uid, s_addr, r_addr);


}

function ssh_postponed(ts: time, s_addr: addr, r_addr: addr, uid: string, data_src: string, aux: string, meth: string)
{

	print sshd_auth_log, fmt("%.6f %s %s POSTPONED %s %s @ %s -> %s",
		ts, aux, data_src, meth, uid, s_addr, r_addr);

}
