#
# $Id: sshd_analyzer.bro,v 1.2 2011/01/24 19:36:39 bro Exp bro $
#
# 01/05/2009: Scott Campbell
#
# sshd_analyzer.bro takes events from an instrumented sshd and 
#   creates summary notices and logs all data as accuratly as possible
#
# in addition, the functionality currently in place from syslog hosts is
#   augmented by this functionality
#
# this version 

# primary keys are:
#	server_id: <server-pid>_<listen-ip>_<listen-port> string
#	client_id: <client-pid>	count
#

#@load hot-ids
#@load listen-clear
#@load notice
#@load login

module SSHD_ANALYZER;

export {

	redef enum Notice::Type += {
		SSHD_Hostile,
		SSHD_SuspicousThreshold,
		SSHD_Suspicous,
		SSHD_Heartbeat,
		SSHD_NewHeartbeat,
		SSHD_RemoteExecHostile,
	};

	global sshd_log: file = open_log_file("sshd");
	global sshd_audit_log: file = open_log_file("sshd_audit");
	
	######################################################################################
	#  data structs and tables
	#
	######################################################################################
	global c_record_clean: function(t: table[count] of int, idx:count) : interval;
	
	type client_record: record {
		conn: connection;
		uid: string &default = "UNKNOWN";
		auth_type: string &default = "UNKNOWN";
		auth_state: count &default=1;		# used to track failed logins vs.successful logins
							# 0 = fail, 1 = default, 2 = success
		summary_count: count &default = 0;	# running total for suspicous commands
		client_tag: count &default = 0;		# unique id
		start_time: time ;			#&default = "1192593206.781399";

		# this allows up to keep track of client/server requests and
		# responses per channel.  each client data line resets the counter
		# while each server response increments it.
		channel_state: table[count] of int  &persistent &expire_func=c_record_clean &write_expire = 10 mins;
		s_commands: set[string];		# list of suspicous commands entered
	};

	type server_record: record {
		# put in a rate monitor here as well ..	
		c_records: table[count] of client_record;	# this is a table of client_record types
		current_clients: count;
		active: count;				# have we received a sshd_stop event for this instance?
		start_time: time;
		heartbeat_seen: bool &default=F;
		heartbeat_last: double;
		interface_list: string &default = "EMPTY";	# list of reported interfaces filtered by populate_address() function
	};

	# function for heartbeat utility
	global s_record_clean: function(t: table[string] of server_record, idx:string) : interval;
	# functions for testing client and server records
	global test_sid: function(sid: string) : server_record;
	global test_cid: function(sid: string, cid: count) : client_record;
	# function for auditing usage
	global sshd_audit: function(call: string);

	# this is a table holding all the known server instances
	global s_records: table[string] of server_record  &persistent &expire_func=s_record_clean &write_expire = 24 hr;

	# in order to keep track of usage, we have a table which records which events are used
	global sshd_auditor: table[string] of count;

	# global sshd index for sessions
	global s_index: count = 0;

	######################################################################################
	#  configuration
	#
	######################################################################################

	# suspicous commands 
	global notify_suspicous_command = T &redef;

	global suspicous_threshold: count = 5 &redef;
	global suspicous_command_list = 
		/^who/
		| /^id[\ ]*$/
		| /^last/
		| /^cd .ssh/
		| /^finger/
		#| /^uname/
		| /^modinfo/
		| /^modprobe/
		| /^mount/
		| /^rpcinfo/
		| /^suexec/
		| /^adduser/
		| /^chat/
	&redef;

	# this set of commands should be alarmed on when executed
	#  remotely
	global alarm_remote_exec =
		/sh -i/
		| /bash -i/
		| /tcsh -i/
		| /csh -i/
		| /uname -a/
		| /unset HISTFILE/
		| /unset[ \t]+(histfile|history|HISTFILE|HISTORY)/
	&redef;

	# whitelist for alarm_remote_exec, if the command is in the whitelist,
	#  don't report it
	global remote_exec_whitelist =
		/PS1=P_R_O_M_P_T/
	&redef;

	const user_white_list =
		/^billybob$/
	&redef;

	# heartbeat timeout interval ...
	const heartbeat_timeout = 300 sec &redef;

	# Data formally from login.bro - this has been imported to avoid compatability
	# issues
	#
	const input_trouble =
	/rewt/
	| /eggdrop/
	| /\/bin\/eject/
	| /oir##t/
	| /ereeto/
	| /(shell|xploit)_?code/
	| /execshell/
	| /ff\.core/
	| /unset[ \t]+(histfile|history|HISTFILE|HISTORY)/
	| /neet\.tar/
	| /r0kk0/
	| /su[ \t]+(daemon|news|adm)/
	| /\.\/clean/
	| /rm[ \t]+-rf[ \t]+secure/
	| /cd[ \t]+\/dev\/[a-zA-Z]{3}/
	| /solsparc_lpset/
	| /\.\/[a-z]+[ \t]+passwd/
	| /\.\/bnc/
	| /bnc\.conf/
	| /\"\/bin\/ksh\"/
	| /LAST STAGE OF DELIRIUM/
	| /SNMPXDMID_PROG/
	| /snmpXdmid for solaris/
	| /\"\/bin\/uname/
	| /gcc[ \t]+1\.c/
	| />\/etc\/passwd/
	| /lynx[ \t]+-source[ \t]+.*(packetstorm|shellcode|linux|sparc)/
	| /gcc.*\/bin\/login/
	| /#define NOP.*0x/
	| /printf\(\"overflowing/
	| /exec[a-z]*\(\"\/usr\/openwin/
	| /perl[ \t]+.*x.*[0-9][0-9][0-9][0-9]/
	| /ping.*-s.*%d/
	&redef;

	 const output_trouble =
	 /^-r.s.*root.*\/bin\/(sh|csh|tcsh)/
	 | /Jumping to address/
	 | /Jumping Address/
	 | /smashdu\.c/
	 | /PATH_UTMP/
	 | /Log started at =/
		 | /www\.anticode\.com/
	 | /www\.uberhax0r\.net/
	 | /smurf\.c by TFreak/
	 | /Super Linux Xploit/
	 | /^# \[root@/
	 | /^-r.s.*root.*\/bin\/(time|sh|csh|tcsh|bash|ksh)/
	 | /invisibleX/
	 | /PATH_(UTMP|WTMP|LASTLOG)/
	 | /[0-9]{5,} bytes from/
	 | /(PATH|STAT):\ .*=>/
	 | /----- \[(FIN|RST|DATA LIMIT|Timed Out)\]/
	 | /IDLE TIMEOUT/
	 | /DATA LIMIT/
	| /-- TCP\/IP LOG --/
	| /STAT: (FIN|TIMED_OUT) /
	| /(shell|xploit)_code/
	| /execshell/
	| /x86_bsd_compaexec/
	| /\\xbf\\xee\\xee\\xee\\x08\\xb8/ # from x.c worm
	| /Coded by James Seter/
	| /Irc Proxy v/
	| /Daemon port\.\.\.\./
	| /BOT_VERSION/
	| /NICKCRYPT/
	| /\/etc\/\.core/
	| /exec.*\/bin\/newgrp/
	| /deadcafe/
	| /[ \/]snap\.sh/
	| /Secure atime,ctime,mtime/
	| /Can\'t fix checksum/
	| /Promisc Dectection/
	| /ADMsn0ofID/
	| /(cd \/; uname -a; pwd; id)/
	| /drw0rm/
	| /[Rr][Ee3][Ww][Tt][Ee3][Dd]/
	| /rpc\.sadmin/
	| /AbraxaS/
	| /\[target\]/
	| /ID_SENDSYN/
	| /ID_DISTROIT/
	| /by Mixter/
	| /rap(e?)ing.*using weapons/
	| /spsiod/
	| /[aA][dD][oO][rR][eE][bB][sS][dD]/ # rootkit
	&redef;

	#

} # end of export

######################################################################################
#  external values
#
######################################################################################

redef Communication::nodes += {
	["sshd2"] = [$host = 127.0.0.1, $events = /.*/, $connect=F, $ssl=F],
};

#redef listen_if_clear = 127.0.0.1;

#redef notice_action_filters += {
#	[SSHD_RemoteExecHostile] = send_email_notice,
#	#[SSHD_RemoteExecHostile] = send_page_notice,
#};

######################################################################################
#  functions 
#
######################################################################################
function create_connection(s_ip: addr, s_port: port, r_ip: addr, r_port: port, ts: time): connection
{
	local s_set: set[string];
	add s_set["ssh-login"];
	
	local c: connection;

	local id: conn_id;
	local orig: endpoint;
	local resp: endpoint;

	id$orig_h = s_ip;
	id$orig_p = s_port;
	id$resp_h = r_ip;
	id$resp_p = r_port;

	orig$size = 0;
	orig$state = 0;
	resp$size = 0;
	resp$state = 0;

	c$id = id;
	c$orig = orig;
	c$resp = resp;
	c$start_time = ts;
	c$duration = 0 sec;

	c$service = s_set;
	c$addl = "";
	c$hot = 0;

	return c;
}

function sshd_audit(call: string)
{
	# look and see if this is a new call
	if ( call !in sshd_auditor )
		{
		local t_call: string = call;
		
		sshd_auditor[t_call] = 0;
		}

	# just increment the name
	++sshd_auditor[call];

	return;
}

function test_sid(sid: string): server_record
{
	# this function will test to see if the sid is in the current
	#    list of known.  if so it is returned, else a new record is 
	#    created.
	local t_server_record: server_record;

	if ( sid ! in s_records ) {
		# this is an unknown instance so we
		# create something new
		t_server_record$current_clients = 0;
		t_server_record$active = 1;
		s_records[sid] = t_server_record;

		#print fmt("%.6f add_sid 2 %s ", network_time(), sid);
	}
	else {
		t_server_record = s_records[sid];
	}
	
	return t_server_record;
}

function test_cid(sid: string, cid: count): client_record
{
	# this function first checks the sid, then the cid.  if the cid
	#  is created, it will be nearly empty - we will fill it in later
	#  in the calling event.
	local t_client_rec: client_record;

	# first check the sid
	local t_server_rec = test_sid(sid);

	if ( cid !in t_server_rec$c_records ) {

		# create a new rec and insert it into the table
		# first increment the client session identifier
		++s_index;
		t_client_rec$client_tag = s_index;

		# create a blank table for channel state
		local t_cs:table[count] of int;
		t_client_rec$channel_state = t_cs;

		# now fill in the blank connection values
		t_client_rec$conn$id$orig_h = 0.0.0.0;
		t_client_rec$conn$id$orig_p = 0/tcp;
		t_client_rec$conn$id$resp_h = 0.0.0.0;
		t_client_rec$conn$id$resp_p = 0/tcp;

		t_server_rec$c_records[cid] = t_client_rec;

		#print fmt("%.6f add_cid 2 %s %s", network_time(), sid, cid);
	}
	else {
		t_client_rec = t_server_rec$c_records[cid];
	}

	return t_client_rec;
}

function save_cid(sid: string, cid: count, cr: client_record)
	{
	s_records[sid]$c_records[cid] = cr;
	}

function parse_line(data: string) : set[string]
	{
	# the data field contains some sort of hostile content.
	# we parse through it and return the offending command 
	# if possible.  

	local return_set: set[string];
	local return_string:string = "NONE";
	local sc_element:count;
	local space_element:count;

	local split_on_sc = split(data, /;/);

	for ( sc_element in split_on_sc ) {
		# now split ; separated commands up on space
		local split_on_space = split(split_on_sc[sc_element], / /);

		for ( space_element in split_on_space ) {

			if ( suspicous_command_list in split_on_space[space_element] && 
				split_on_space[space_element] !in return_set) {

				add return_set[ split_on_space[space_element] ];
				print fmt("seen hostile command: %s", split_on_space[space_element]);
			}
			
			# in addition to looking at the raw string, we can do a comparison against
			#  a translated string as well where we are taking a stab at clearing out the 
			#  junk from color and meta characters.  This is a gross hack.  We translate
			#  like 'sed s/\\[..//g' .
			#  given string s, run addl_str = sub(addl_str, /^\[/, "")
			local trans_string:string = sub(split_on_space[space_element], /\[../, "");

			if ( suspicous_command_list in trans_string && 
				split_on_space[space_element] !in return_set) {

				add return_set[ trans_string ];
				print fmt("seen translated hostile command: %s", trans_string);
			}
		} 
	} # end ; for-loop

	return return_set;
	}

function test_suspicous(data:string, CR: client_record, channel:count, sid:string, cid:count) : int
	{
	# Do test(s) for hostile content on the returned text element as it 
	#  ought to be a little cleaner then what the user typed.  Note that 
	#  we now have *two* lists of regular expressions for suspicous behavor.  
	# The first is more general and is used to look for candidates, 
	#  while the second is more exact.
	
	local ret= 0; # nothing to see ...

	if ( suspicous_command_list in data ) {
	
		# suspicous == incrementaly hostile

		# now figure out exactly which command was issued since
		# we are tracking unique instances - there might be > 1
		# so we return a set of values 
		local s_set: set[string];
		local s_set_element: string;
		s_set = parse_line(data);	

		# the set 's_set' contains (one/multiple) commands which have been identified as hostile.
		# go through them and make sure that the current CR has not counted them already
		for ( s_set_element in s_set ) {

			if ( s_set_element !in CR$s_commands ) {
				add CR$s_commands[s_set_element];

				++CR$summary_count;

				if ( (notify_suspicous_command) && (CR$summary_count <= suspicous_threshold) ) {
	
					NOTICE([$note=SSHD_Suspicous,
						$msg=fmt("#%s %s %s %s %s @ %s -> %s:%s command: %s",
						CR$client_tag, channel, sid, cid, CR$uid,
						CR$conn$id$orig_h, CR$conn$id$resp_h, 
						CR$conn$id$resp_p, s_set_element)]);
					}

				if ( CR$summary_count == suspicous_threshold ) {

					local t_s: string = " ";
					local r_s: string = " ";

					for ( t_s in CR$s_commands ) {
						r_s = fmt("%s %s", r_s, t_s);
					}

					NOTICE([$note=SSHD_SuspicousThreshold,
						$msg=fmt("#%s %s %s %s %s @ %s -> %s %s:%s {%s}",
						CR$client_tag, channel, sid, cid, CR$uid, 
						CR$conn$id$orig_h, sid, CR$conn$id$resp_h, 
						CR$conn$id$resp_p, r_s)]);
				}
			}

		} #end for
		
		ret = 1;
	}
	
	return ret;
	}

function test_remote_exec(data: string, CR: client_record, sid:string, cid:count) : int
	{
	local ret = 0;

	if ( alarm_remote_exec in data && remote_exec_whitelist !in data ) {
	
		NOTICE([$note=SSHD_RemoteExecHostile,
		$msg=fmt("#%s - %s %s %s @ %s -> %s:%s command: %s",
		CR$client_tag, sid, cid, CR$uid, 
		CR$conn$id$orig_h, CR$conn$id$resp_h, 
		CR$conn$id$resp_p, data)]);
			
		ret = 1;
		}
		
	return ret;
	}

function test_hostile_client(data:string, CR: client_record, channel:count, sid:string, cid:count) : int
	{
	local ret = 0; # nothing to see ...

	if ( input_trouble in data ) {
	
		NOTICE([$note=SSHD_Hostile,
		$msg=fmt("#%s %s %s %s %s @ %s -> %s:%s command: %s",
		CR$client_tag, channel, sid, cid, CR$uid, 
		CR$conn$id$orig_h, CR$conn$id$resp_h, 
		CR$conn$id$resp_p, data)]);
				
		ret = 1;
		}
		
	return ret;
	
	}

function test_hostile_server(data:string, CR: client_record, channel:count, sid:string, cid:count) : int
	{
	local ret = 0; # nothing to see ...

	if ( output_trouble in data ) {
	
		NOTICE([$note=SSHD_Hostile,
		$msg=fmt("#%s %s %s %s %s @ %s -> %s:%s output: %s",
		CR$client_tag, channel, sid, cid, CR$uid, 
		CR$conn$id$orig_h, CR$conn$id$resp_h, 
		CR$conn$id$resp_p, data)]);
				
		ret = 1;
		}
		
	return ret;
	
	}

function remove_cid(sid:string, cid:count) : int
	{
	local ret:int = 1;

	if ( sid in s_records ) 

		if ( cid in s_records[sid]$c_records ) {

			# now that we have a record, start removing things
			local c: count;

			for ( c in s_records[sid]$c_records[cid]$channel_state ) {
				delete s_records[sid]$c_records[cid]$channel_state[c];
				#print fmt("%.6f remove_cid 2 %s : %s : chnl %s", network_time(), sid, cid, c);
				}

			delete s_records[sid]$c_records[cid];
			#print fmt("%.6f remove_cid 2 %s : %s ", network_time(), sid, cid);
			ret = 0;
		}
	return ret;

	}

function remove_sid(sid:string) : int
	{
	local ret:int = 1;
	local t_cid: count;

	print "call removesid";

	if ( sid in s_records ) {

		for ( t_cid in s_records[sid]$c_records )
			remove_cid(sid, t_cid);

		delete s_records[sid];
		print fmt("%.6f remove_sid 2 %s ", network_time(), sid);
		ret = 0;
	}

	return ret;
	}

function s_record_clean(t: table[string] of server_record, idx:string) : interval
	{
	remove_sid(idx);
	return 0 secs;
	}

function c_record_clean(t: table[count] of int, idx:count) : interval
	{
	# for the time being, see if the s-record_clean will take care of any issues
	# if not, just add another field to the client_record holding the sid
	print fmt("%.6f c-rec-clecn: %s", network_time(), idx);

	#remove_cid(idx);
	return 0 secs;
	}

######################################################################################
#  events
#
######################################################################################


event sshd_start_2(ts: time, version: string, serv_interfaces: string, sid: string, s_a: addr, s_p: port)
	{
	sshd_audit("sshd_start");

	local t_sid: server_record;
	t_sid = test_sid(sid);
	
	t_sid$start_time = ts;
	s_records[sid] = t_sid;

	print sshd_log, fmt("%.6f sshd_start %s:%s %s", ts, s_a, s_p, sid);
	}

event sshd_exit_2(ts: time, version: string, serv_interfaces: string, sid: string, s_a: addr, s_p: port)
	{
	sshd_audit("sshd_exit");

	local t_sid: server_record;
	t_sid = test_sid(sid);
	
	t_sid$start_time = ts;
	s_records[sid] = t_sid;
	# add dt here
	print sshd_log, fmt("%.6f sshd_exit %s:%s %s", ts, s_a, s_p, sid);
	}

event ssh_connection_start_2(ts:time, version: string, serv_interfaces: string, sid:string, s_addr:addr, s_port:port, r_addr:addr, r_port:port, cid:count)
	{
	sshd_audit("ssh_connection_start");

	local CR:client_record = test_cid(sid,cid);
	print sshd_log, fmt("%.6f #%s - %s %s ssh_connection_start %s:%s > %s:%s",
		ts, CR$client_tag, sid, cid, s_addr, s_port, r_addr, r_port);
	}

event ssh_connection_end_2(ts:time, version: string, serv_interfaces: string, sid:string, s_addr:addr, s_port:port, r_addr:addr, r_port:port, cid:count)
	{
	sshd_audit("ssh_connection_end");

	local CR:client_record = test_cid(sid,cid);

	if ( CR$auth_state == 0 ) {
		# increment the auth_fail for ssh scan
		}
	remove_cid(sid, cid);

	print sshd_log, fmt("%.6f #%s - %s %s ssh_connection_end %s:%s > %s:%s",
		ts, CR$client_tag, sid, cid, s_addr, s_port, r_addr, r_port);

	}


#event auth_ok_2(ts:time, version: string, serv_interfaces: string, sid:string, uid:string, authtype:string, s_addr: addr, s_port: port, r_addr: addr, r_port: port, cid: count)
event auth_ok_2(ts:time, sid: string, version: string, serv_interfaces: string, uid:string, authtype:string, s_addr: addr, s_port: port, r_addr: addr, r_port: port, cid: count)
	{
	sshd_audit("auth_ok");

	local CR:client_record = test_cid(sid,cid); # this will probably be a new record
	local SR:server_record = test_sid(sid);

	# fill in a few additional records inthe client and server records
	CR$conn = create_connection(s_addr, s_port, r_addr,r_port,ts);
	CR$uid = uid;
	CR$auth_type = authtype;
	CR$auth_state = 1;
	#++CR$summary_count;
	CR$start_time = ts;

	++SR$current_clients;

	SR$c_records[cid] = CR;
	s_records[sid] = SR;

	print sshd_log, fmt("%.6f #%s - %s %s auth_ok %s %s %s:%s > %s:%s", 
		ts, CR$client_tag, sid, cid, uid, authtype, s_addr, s_port, r_addr, r_port);
	}

event auth_fail_2(ts:time, version: string, serv_interfaces: string, sid:string, uid:string, authtype:string, s_addr: addr, s_port: port, r_addr: addr, r_port: port, cid: count)
	{
	sshd_audit("auth_fail");

	local CR:client_record = test_cid(sid,cid); # this will probably be a new record
	local SR:server_record = test_sid(sid);

	# fill in a few additional records inthe client and server records
	CR$conn = create_connection(s_addr, s_port, r_addr,r_port,ts);
	CR$uid = uid;
	CR$auth_type = authtype;
	CR$auth_state = 0;
	#++CR$summary_count;
	CR$start_time = ts;

	SR$c_records[cid] = CR;
	s_records[sid] = SR;

	print sshd_log, fmt("%.6f #%s - %s %s auth_fail %s %s %s:%s > %s:%s", 
		ts, CR$client_tag, sid, cid, uid, authtype, s_addr, s_port, r_addr, r_port);
	}

#event invalid_user_2(ts:time, version: string, serv_interfaces: string, sid:string, uid:string, cid: count)
event invalid_user_2(ts:time, sid:string, version: string, serv_interfaces: string, uid:string, cid: count)
	{
	sshd_audit("invalid_user");

	local CR:client_record = test_cid(sid,cid);

	print sshd_log, fmt("%.6f #%s - %s %s invalid_user: %s", ts, CR$client_tag, sid, cid, uid);
	}


event new_session_2(ts:time, version: string, serv_interfaces: string, sid:string, ver:string, cid:count)
	{
	sshd_audit("new_session");

	local CR:client_record = test_cid(sid,cid);

	print sshd_log, fmt("%.6f #%s - %s %s new_session %s", ts, CR$client_tag, sid, cid, ver);
	}

event new_channel_session_2(ts:time, version: string, serv_interfaces: string, sid:string, channel:count, channel_type:string, cid:count)
	{
	sshd_audit("new_channel_session");

	local CR:client_record = test_cid(sid,cid);
	CR$channel_state[channel] = 0;
	save_cid(sid,cid,CR);
	print sshd_log, fmt("%.6f #%s %s %s %s new_channel_session %s", ts, CR$client_tag, channel, sid, cid, channel_type);

	}

event server_request_direct_tcpip_2(ts:time, version: string, serv_interfaces: string, sid:string, s_addr:string, s_port: port, r_addr: string, r_port: port, cid: count)
	{
	# This is one of several channel types described in serverloop.c:server_input_channel_open()
	# The options are: "session", "direct-tcp" and "tun@openssh.com"

	sshd_audit("server_request_direct_tcpip");

	local CR:client_record = test_cid(sid,cid);

	print sshd_log, fmt("%.6f #%s - %s %s server_request_direct_tcpip %s:%s > %s:%s", 
		ts, CR$client_tag, sid, cid, s_addr, s_port, r_addr, r_port);
	}

#event ssh_remote_exec_pty_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, data:string)
event ssh_remote_exec_no_pty_2(ts:time, sid:string, version:string, serv_interfaces:string, cid:count, data:string)
	{
	# This is called to fork and execute a command when we have no tty.  This
	# will call do_child from the child, and server_loop from the parent after
	# setting up file descriptors and such.

	sshd_audit("ssh_remote_exec_pty");

	local CR:client_record = test_cid(sid,cid);

	test_remote_exec(data, CR, sid, cid);

	print sshd_log, fmt("%.6f #%s %s ssh_remote_exec_no_pty %s", ts, CR$client_tag, sid, data);

	}

#event ssh_do_exec_pty_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, data:string)
event ssh_remote_exec_pty_2(ts:time, sid:string, cid:count, data:string) 
	{
	# This is called to fork and execute a command when we have a tty.  This
	# will call do_child from the child, and server_loop from the parent after
	# setting up file descriptors, controlling tty, updating wtmp, utmp,
	# lastlog, and other such operations.

	sshd_audit("ssh_do_exec_pty");

	local CR:client_record = test_cid(sid,cid);

	test_remote_exec(data, CR, sid, cid);

	print sshd_log, fmt("%.6f #%s - %s %s ssh_do_exec_pty %s", ts, CR$client_tag, sid, cid, data);
	}

#event ssh_remote_do_exec_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, data:string)
event ssh_remote_do_exec_2(ts:time, sid:string, version:string, serv_interfaces: string, cid:count, data:string)
	{
	# This is called to fork and execute a command.  If another command is
	# to be forced, execute that instead.

	sshd_audit("ssh_remote_do_exec");

	local CR:client_record = test_cid(sid,cid);

	test_remote_exec(data, CR, sid, cid);

	print sshd_log, fmt("%.6f #%s - %s %s ssh_remote_do_exec %s", ts, CR$client_tag, sid, cid, data);
	}

event data_server_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, data:string)
	{
	sshd_audit("data_server");

	local CR:client_record = test_cid(sid,cid);

	# if the bro instance has started up while sessions are running, you
	# will reference non-existant channels.  we fix that here.
	if ( channel !in CR$channel_state ) {
		CR$channel_state[channel] = 0;	# reset the channel state
	}

	test_hostile_server(data, CR, channel, sid, cid);

	save_cid(sid,cid,CR);

	print sshd_log, fmt("%.6f #%s %s %s %s data_server %s", ts, CR$client_tag, channel, sid, cid, data);
	}

event data_server_sum(ts: time, sid: string, version: string, serv_interfaces: string,cid: count, channel: count, bytes_skip: count)
	{
	sshd_audit("data_server_sum");

	local CR:client_record = test_cid(sid,cid);

	# if the bro instance has started up while sessions are running, you
	# will reference non-existant channels.  we fix that here.
	if ( channel !in CR$channel_state ) {
		CR$channel_state[channel] = 0;	# reset the channel state
	}

	save_cid(sid,cid,CR);

	print sshd_log, fmt("%.6f #%s %s %s %s data_server_sum %s", ts, CR$client_tag, channel, sid, cid, bytes_skip);

	}


event data_server_sum_2(ts: time, sid: string, version: string, serv_interfaces: string,cid: count, channel: count, bytes_skip: count)
	{
	sshd_audit("data_server_sum_2");

	local CR:client_record = test_cid(sid,cid);

	# if the bro instance has started up while sessions are running, you
	# will reference non-existant channels.  we fix that here.
	if ( channel !in CR$channel_state ) {
		CR$channel_state[channel] = 0;	# reset the channel state
	}

	save_cid(sid,cid,CR);

	print sshd_log, fmt("%.6f #%s %s %s %s data_server_sum %s", ts, CR$client_tag, channel, sid, cid, bytes_skip);

	}

event data_client_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, data:string)
	{
	sshd_audit("sshd_client");

	local CR:client_record = test_cid(sid,cid);

	# if the bro instance has started up while sessions are running, you
	# will reference non-existant channels.  we fix that here.
	if ( channel !in CR$channel_state ) {
		CR$channel_state[channel] = 0;
	}

	# run the client data through the suspicous and hostile tests.  see comments
	#  in the assosciated functions for differences in the symantics.
	test_suspicous(data, CR, channel, sid, cid);

	test_hostile_client(data, CR, channel, sid, cid);

	++CR$channel_state[channel];
	save_cid(sid,cid,CR);

	print sshd_log, fmt("%.6f #%s %s %s %s data_client %s", ts, CR$client_tag, channel, sid, cid, data);
	}

event ssh_pass_attempt_2(ts: time, version: string, serv_interfaces: string, sid: string, uid: string, pass: string, cid: count)
	{
	# this event handles the password exchane so that we can hunt them down
	# and erase the events at a later time if required

	sshd_audit("ssh_pass_attempt");

	local CR:client_record = test_cid(sid,cid);

	print sshd_log, fmt("%.6f #%s - %s %s %s password: %s", ts, CR$client_tag, sid, cid, uid, pass);
	}

#event server_heartbeat_2(ts: time, version: string, serv_interfaces: string, sid: string, dt: count)
#	{
#	sshd_audit("server_heartbeat");
#
#	local SR:server_record = test_sid(sid);
#	local RE: bool = is_remote_event();
#	local ts_d:double = time_to_double(ts);
#
#	# there is case where the SR has been reaped but there is still 
#	#  a heartbeat timer for it.  quick check then bail
#	if ( ! SR$heartbeat_seen && ! RE ) {
#		return;
#	}
#
#	# first time we have seen a heartbeat?
#	if ( ! SR$heartbeat_seen ) {
#		# first time we have seen a heartbeat from this system
#		SR$heartbeat_seen = T;
#		SR$heartbeat_last = ts_d;
#
#		s_records[sid] = SR;
#
#		NOTICE([$note=SSHD_NewHeartbeat,
#			$msg=fmt("New communication from %s", sid)]);
#	}
#	else {
#		# this is a actual test case ...
#		if ( ( ts_d - SR$heartbeat_last ) > interval_to_double(heartbeat_timeout) ) {
#			
#			# the simple model here is that we will look for local generated
#			#  heartbeat events as a legitimate test of the system being up.
#			# Perhaps I ought to make somethign a little smarter before the
#			#  next daylight savings time??
#			if ( ! RE ) {
#				NOTICE([$note=SSHD_Heartbeat,
#					$msg=fmt("Lost communication to %s, dt=%s",
#						sid, ts_d - SR$heartbeat_last)]);
#				
#				SR$heartbeat_seen = F;
#			}
#
#		} # End dt test for heartbeat
#
#		SR$heartbeat_last = ts_d;
#		s_records[sid] = SR;
#
#	}
#
#	local hb_sched:interval = heartbeat_timeout + rand(10) * 1 sec;
#	local new_time = double_to_time( interval_to_double(hb_sched) + ts_d );
#
#	schedule hb_sched { server_heartbeat_2( new_time, version, serv_interfaces, sid, 0) };
#	
#	}
	
# The following two events are for applications that do not spawn an assosciated tty
#  for the ssh connection.  This is also used for sftp data transfer so we have some
#  additional code and testing 

#  sshd_key_fingerprint time=0,1229560679.459008 string=30,49156_dhcp162-8.nersc.gov_2222 count=0,49159 
#		string=47,05:b1:35:1a:7f:dd:82:0d:39:91:07:0c:37:ac:16:45 string=3,DSA
#  ssh_remote_do_exec time=0,1229584625.928213 string=21,49497_DOE6684452_2222 count=0,49878 string=5,sh -i
#  ssh_remote_exec_no_pty time=0,1229584625.928251 string=21,49497_DOE6684452_2222 count=0,49878 string=5,sh -i
#  new_channel_session time=0,1229584625.928686 string=21,49497_DOE6684452_2222 count=0,0 string=0,exec count=0,49878

event notty_client_data_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, data:string)
	{
	sshd_audit("notty_client_data");

	local CR:client_record = test_cid(sid,cid);

	# if the bro instance has started up while sessions are running, you
	# will reference non-existant channels.  we fix that here.
	if ( channel !in CR$channel_state ) {
		CR$channel_state[channel] = 0;
	}

	# run the client data through the suspicous and hostile tests.  see comments
	#  in the assosciated functions for differences in the symantics.
	# For the notty check, this may introduce too many false positives and may
	#  have to be removed.
	#
	test_suspicous(data, CR, 0, sid, cid);

	test_hostile_client(data, CR, 0, sid, cid);

	print sshd_log, fmt("%.6f #%s %s %s %s notty_data_client %s", ts, CR$client_tag, channel, sid, cid, data);
	
	}
	
event notty_server_data_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, data:string)
	{
	sshd_audit("notty_server_data");
	local CR:client_record = test_cid(sid,cid);

	# if the bro instance has started up while sessions are running, you
	# will reference non-existant channels.  we fix that here.
	if ( channel !in CR$channel_state ) {
		CR$channel_state[channel] = 0;
	}

	test_suspicous(data, CR, 0, sid, cid);

	test_hostile_server(data, CR, 0, sid, cid);

	print sshd_log, fmt("%.6f #%s %s %s %s notty_data_server %s", ts, CR$client_tag, channel, sid, cid, data);
	
	}

event notty_analysis_disable_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, byte_skip: int, byte_allow: int)
	{
	sshd_audit("notty_analysis_disable");

	local CR:client_record = test_cid(sid,cid);

	print sshd_log, fmt("%.6f #%s - %s %s notty_analysis_disable %s skip %s allow", ts, CR$client_tag, sid, cid, byte_skip, byte_allow);
	}

#event sshd_key_fingerprint_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, fingerprint:string, key_type:string)
event sshd_key_fingerprint_2(ts:time, sid: string, version: string, serv_interfaces: string, cid:count, fingerprint:string, key_type:string)
	{
	sshd_audit("sshd_key_fingerprint");

	local CR:client_record = test_cid(sid,cid);

	print sshd_log, fmt("%.6f #%s - %s %s ssh_client_key_fingerprint %s type %s", ts, CR$client_tag, sid, cid, fingerprint, key_type);
	}

event bro_done()
	{
	# print to sshd_audit_log

	local s: string;

	print sshd_audit_log, fmt("SSHD function/event     Count");
	print sshd_audit_log, fmt("-----------------------------");

	for ( s in sshd_auditor )
		{
		print sshd_audit_log, fmt("%s     %s", s, sshd_auditor[s]);
		}
	
	print sshd_audit_log, fmt("-----------------------------");

	}
