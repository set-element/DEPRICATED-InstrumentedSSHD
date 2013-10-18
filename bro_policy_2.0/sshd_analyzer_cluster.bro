#
# $Id: sshd_analyzer_cluster.bro,v 2 2013/10/14 
#
# 2013/10/14: Scott Campbell
#
# sshd_analyzer.bro takes events from an instrumented sshd and 
#   creates summary notices and logs all data as accuratly as possible
#
# in addition, the functionality currently in place from syslog hosts is
#   augmented by this functionality
#
# this version is designed for a clustered environment so that all output
#  is passed through the same logging framework as the newer sshd_core 
#  policy.  In fact we will piggyback off that code to avoid inconsistancies...
#

# primary keys are:
#	server_id: <server-pid>_<listen-ip>_<listen-port> string
#	client_id: <client-pid>	count
#
# for cluster we need the following:
@load sshd_core_cluster

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

	######################################################################################
	#  data structs and tables
	#
	######################################################################################

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
function create_connection(s_ip: addr, s_port: port, r_ip: addr, r_port: port, ts: time): conn_id
{
	local t_id: conn_id;

	t_id$orig_h = s_ip;
	t_id$orig_p = s_port;
	t_id$resp_h = r_ip;
	t_id$resp_p = r_port;

	return t_id;
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
			}
		} 
	} # end ; for-loop

	return return_set;
	}

function test_suspicous(data:string, CR: SSHD_CORE::client_record, channel:count, sid:string, cid:count) : int
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

				if ( (notify_suspicous_command) && ( |CR$s_commands| <= suspicous_threshold) ) {
	
					NOTICE([$note=SSHD_Suspicous,
						$msg=fmt("%s %s %s %s %s @ %s -> %s:%s command: %s",
						CR$log_id, channel, sid, cid, CR$uid,
						CR$id$orig_h, CR$id$resp_h, 
						CR$id$resp_p, s_set_element)]);
					}

				if ( |CR$s_commands| == suspicous_threshold ) {

					local t_s: string = " ";
					local r_s: string = " ";

					for ( t_s in CR$s_commands ) {
						r_s = fmt("%s %s", r_s, t_s);
					}

					NOTICE([$note=SSHD_SuspicousThreshold,
						$msg=fmt("%s %s %s %s %s @ %s -> %s %s:%s {%s}",
						CR$log_id, channel, sid, cid, CR$uid, 
						CR$id$orig_h, sid, CR$id$resp_h, 
						CR$id$resp_p, r_s)]);
				}
			}

		} #end for
		
		ret = 1;
	}
	
	return ret;
	}

function test_remote_exec(data: string, CR: SSHD_CORE::client_record, sid:string, cid:count) : int
	{
	local ret = 0;

	if ( alarm_remote_exec in data && remote_exec_whitelist !in data ) {
	
		NOTICE([$note=SSHD_RemoteExecHostile,
		$msg=fmt("%s - %s %s %s @ %s -> %s:%s command: %s",
		CR$log_id, sid, cid, CR$uid, 
		CR$id$orig_h, CR$id$resp_h, 
		CR$id$resp_p, data)]);
			
		ret = 1;
		}
		
	return ret;
	}

function test_hostile_client(data:string, CR: SSHD_CORE::client_record, channel:count, sid:string, cid:count) : int
	{
	local ret = 0; # nothing to see ...

	if ( input_trouble in data ) {
	
		NOTICE([$note=SSHD_Hostile,
		$msg=fmt("%s %s %s %s %s @ %s -> %s:%s command: %s",
		CR$log_id, channel, sid, cid, CR$uid, 
		CR$id$orig_h, CR$id$resp_h, 
		CR$id$resp_p, data)]);
				
		ret = 1;
		}
		
	return ret;
	
	}

function test_hostile_server(data:string, CR: SSHD_CORE::client_record, channel:count, sid:string, cid:count) : int
	{
	local ret = 0; # nothing to see ...

	if ( output_trouble in data ) {
	
		NOTICE([$note=SSHD_Hostile,
		$msg=fmt("%s %s %s %s %s @ %s -> %s:%s output: %s",
		CR$log_id, channel, sid, cid, CR$uid, 
		CR$id$orig_h, CR$id$resp_h, 
		CR$id$resp_p, data)]);
				
		ret = 1;
		}
		
	return ret;
	
	}

######################################################################################
#  events
#
######################################################################################


event sshd_start_2(ts: time, version: string, serv_interfaces: string, sid: string, s_a: addr, s_p: port)
	{
	local t_sid: SSHD_CORE::server_record;
	t_sid = SSHD_CORE::test_sid(sid);
	
	t_sid$start_time = ts;
	SSHD_CORE::s_records[sid] = t_sid;

	SSHD_CORE::log_server_session(t_sid, ts, "SSHD_START_2", "SSHD_START_2");
	}

event sshd_exit_2(ts: time, version: string, serv_interfaces: string, sid: string, s_a: addr, s_p: port)
	{
	local t_sid: SSHD_CORE::server_record;
	t_sid = SSHD_CORE::test_sid(sid);
	
	t_sid$start_time = ts;
	SSHD_CORE::s_records[sid] = t_sid;

	SSHD_CORE::log_server_session(t_sid, ts, "SSHD_EXIT_2", "SSHD_EXIT_2");
	}

event ssh_connection_start_2(ts:time, version: string, serv_interfaces: string, sid:string, s_addr:addr, s_port:port, r_addr:addr, r_port:port, cid:count)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local s_data = fmt("%s:%s -> %s:%s %s", s_addr, s_port, r_addr, r_port, serv_interfaces);

	SSHD_CORE::log_session_update_event(CR, ts, "SSHD_CONNECTION_START_2", s_data);
	}

event ssh_connection_end_2(ts:time, version: string, serv_interfaces: string, sid:string, s_addr:addr, s_port:port, r_addr:addr, r_port:port, cid:count)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	local s_data = fmt("%s:%s -> %s:%s %s", s_addr, s_port, r_addr, r_port, serv_interfaces);

	SSHD_CORE::remove_cid(sid, cid);
	SSHD_CORE::log_session_update_event(CR, ts, "SSHD_CONNECTION_END_2", s_data);
	}

event auth_ok_2(ts:time, sid: string, version: string, serv_interfaces: string, uid:string, authtype:string, s_addr: addr, s_port: port, r_addr: addr, r_port: port, cid: count)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid); # this will probably be a new record
	local SR: SSHD_CORE::server_record = SSHD_CORE::test_sid(sid);

	# fill in a few additional records in the client and server records
	CR$id = create_connection(s_addr, s_port, r_addr,r_port,ts);
	CR$uid = uid;
	CR$auth_type = authtype;
	CR$auth_state = 1;
	CR$start_time = ts;

	++SR$current_clients;

	SR$c_records[cid] = CR;
	SSHD_CORE::s_records[sid] = SR;
	
	local authmsg = "Accepted";
	local s_data = fmt("AUTH %s %s %s %s:%s > %s:%s", authmsg, uid, authtype, s_addr, s_port, r_addr, r_port);

	SSHD_CORE::log_update_uid(CR,uid);
	SSHD_CORE::log_session_update_event(CR, ts, "AUTH_INFO_2", s_data);

	local t_key = SSHD_CORE::get_info_key(CR);

	event USER_CORE::auth_transaction(ts, CR$log_id, CR$id, uid, SSHD_CORE::print_sid(sid), "isshd", "authentication", authmsg, authtype, t_key);
	}

event auth_fail_2(ts:time, version: string, serv_interfaces: string, sid:string, uid:string, authtype:string, s_addr: addr, s_port: port, r_addr: addr, r_port: port, cid: count)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid); # this will probably be a new record
	local SR: SSHD_CORE::server_record = SSHD_CORE::test_sid(sid);

	# fill in a few additional records in the client and server records
	CR$id = SSHD_CORE::create_connection(s_addr, s_port, r_addr,r_port,ts);
	CR$uid = uid;
	CR$auth_type = authtype;
	CR$auth_state = 0;
	CR$start_time = ts;

	SR$c_records[cid] = CR;
	SSHD_CORE::s_records[sid] = SR;

	local authmsg = "Failed";
	local s_data = fmt("AUTH %s %s %s %s:%s > %s:%s", authmsg, uid, authtype, s_addr, s_port, r_addr, r_port);

	SSHD_CORE::log_update_uid(CR,uid);
	SSHD_CORE::log_session_update_event(CR, ts, "AUTH_INFO_2", s_data);

	local t_key = SSHD_CORE::get_info_key(CR);

	event USER_CORE::auth_transaction(ts, CR$log_id, CR$id, uid, SSHD_CORE::print_sid(sid), "isshd", "authentication", authmsg, authtype, t_key);
	}

event invalid_user_2(ts:time, sid:string, version: string, serv_interfaces: string, uid:string, cid: count)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	local s_data = fmt("%s:%s > %s @ %s:%s",
		CR$id$orig_h, CR$id$orig_p, CR$id$resp_h, CR$id$resp_p, uid);

	SSHD_CORE::log_update_uid(CR,uid);
	SSHD_CORE::log_session_update_event(CR, ts, "AUTH_INVALID_USER_2", s_data);
	}


event new_session_2(ts:time, version: string, serv_interfaces: string, sid:string, ver:string, cid:count)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	SSHD_CORE::log_update_host(CR, SSHD_CORE::print_sid(sid) );
	SSHD_CORE::log_session_update_event(CR, ts, "SESSION_NEW_2", "SESSION_NEW_2");
	}

event new_channel_session_2(ts:time, version: string, serv_interfaces: string, sid:string, channel:count, channel_type:string, cid:count)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	SSHD_CORE::save_cid(sid,cid,CR);
	CR$channel_type[channel] = to_lower(channel_type);
	local s_data = fmt("%s %s %s", channel, SSHD_CORE::print_channel(CR,channel), to_lower(channel_type));

	SSHD_CORE::log_update_channel(CR,channel);
	SSHD_CORE::log_session_update_event(CR, ts, "CHANNEL_NEW_2", s_data);
	}

event server_request_direct_tcpip_2(ts:time, version: string, serv_interfaces: string, sid:string, s_addr:string, s_port: port, r_addr: string, r_port: port, cid: count)
	{
	# This is one of several channel types described in serverloop.c:server_input_channel_open()
	# The options are: "session", "direct-tcp" and "tun@openssh.com"

	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	local s_data = fmt("%s:%s -> %s:%s", s_addr, s_port, r_addr, r_port);

	SSHD_CORE::log_update_forward(CR, r_addr, r_port);
	SSHD_CORE::log_session_update_event(CR, ts, "SESSION_REQUEST_DIRECT_TCPIP_2", s_data);
	}

event ssh_remote_exec_no_pty_2(ts:time, sid:string, version:string, serv_interfaces:string, cid:count, data:string)
	{
	# This is called to fork and execute a command when we have no tty.  This
	# will call do_child from the child, and server_loop from the parent after
	# setting up file descriptors and such.

	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	test_remote_exec(data, CR, sid, cid);

	local s_data = fmt("%s", str_shell_escape(data));
	SSHD_CORE::log_session_update_event(CR, ts, "SESSION_REMOTE_DO_EXEC_NO_PTY_2", s_data);
	}

event ssh_remote_exec_pty_2(ts:time, sid:string, cid:count, data:string) 
	{
	# This is called to fork and execute a command when we have a tty.  This
	# will call do_child from the child, and server_loop from the parent after
	# setting up file descriptors, controlling tty, updating wtmp, utmp,
	# lastlog, and other such operations.
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	test_remote_exec(data, CR, sid, cid);
	
	local s_data = fmt("%s", str_shell_escape(data));
	SSHD_CORE::log_session_update_event(CR, ts, "SESSION_REMOTE_DO_EXEC_PTY_2", s_data);
	}

event ssh_remote_do_exec_2(ts:time, sid:string, version:string, serv_interfaces: string, cid:count, data:string)
	{
	# This is called to fork and execute a command.  If another command is
	# to be forced, execute that instead.
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	test_remote_exec(data, CR, sid, cid);

	local s_data = fmt("%s", str_shell_escape(data));
	SSHD_CORE::log_session_update_event(CR, ts, "SESSION_REMOTE_DO_EXEC_2", s_data);;
	}

event data_server_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, data:string)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	test_hostile_server(data, CR, channel, sid, cid);

	SSHD_CORE::save_cid(sid,cid,CR);
	SSHD_CORE::log_session_update_event(CR, ts, "CHANNEL_DATA_SERVER_2", data);
	}

event data_server_sum(ts: time, sid: string, version: string, serv_interfaces: string,cid: count, channel: count, bytes_skip: count)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	SSHD_CORE::save_cid(sid,cid,CR);
	local s_data = fmt("%s %s %s",  channel, SSHD_CORE::print_channel(CR,channel), bytes_skip);
	SSHD_CORE::log_session_update_event(CR, ts, "CHANNEL_DATA_SERVER_SUM_1", s_data);
	}


event data_server_sum_2(ts: time, sid: string, version: string, serv_interfaces: string,cid: count, channel: count, bytes_skip: count)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	SSHD_CORE::save_cid(sid,cid,CR);
	local s_data = fmt("%s %s %s",  channel, SSHD_CORE::print_channel(CR,channel), bytes_skip);
	SSHD_CORE::log_session_update_event(CR, ts, "CHANNEL_DATA_SERVER_SUM_1", s_data);
	}

event data_client_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, data:string)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	# run the client data through the suspicous and hostile tests.  see comments
	#  in the assosciated functions for differences in the symantics.
	test_suspicous(data, CR, channel, sid, cid);
	test_hostile_client(data, CR, channel, sid, cid);

	SSHD_CORE::save_cid(sid,cid,CR);
	SSHD_CORE::log_session_update_event(CR, ts, "CHANNEL_DATA_CLIENT_2", data);
	}

event ssh_pass_attempt_2(ts: time, version: string, serv_interfaces: string, sid: string, uid: string, pass: string, cid: count)
	{
	# this event handles the password exchange so that we can hunt them down
	# and erase the events at a later time if required
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	local s_data = fmt("%s",pass);
	SSHD_CORE::log_session_update_event(CR, ts, "AUTH_PASS_ATTEMPT_2", s_data);
	}

# NOTE: the v2 of the protocol had some near pathological issues, so the heartbeat event
#       has been taken out. As this version of the protocol is more or less deprecated, 
#       I will leave this out for now.
#
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
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	# run the client data through the suspicous and hostile tests.  see comments
	#  in the assosciated functions for differences in the symantics.
	# For the notty check, this may introduce too many false positives and may
	#  have to be removed.
	#
	test_suspicous(data, CR, 0, sid, cid);
	test_hostile_client(data, CR, 0, sid, cid);

	SSHD_CORE::log_session_update_event(CR, ts, "CHANNEL_NOTTY_CLIENT_DATA_2", data);
	}
	
event notty_server_data_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, data:string)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	test_suspicous(data, CR, 0, sid, cid);
	test_hostile_server(data, CR, 0, sid, cid);

	SSHD_CORE::log_session_update_event(CR, ts, "CHANNEL_NOTTY_SERVER_DATA_2", data);
	}

event notty_analysis_disable_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, byte_skip: int, byte_allow: int)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	local s_data = fmt("%s %s", byte_skip, byte_allow);
	SSHD_CORE::log_session_update_event(CR, ts, "CHANNEL_NOTTY_ANALYSIS_DISABLE_2", s_data);
	}

event sshd_key_fingerprint_2(ts:time, sid: string, version: string, serv_interfaces: string, cid:count, fingerprint:string, key_type:string)
	{
	local CR: SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

	local s_data = fmt("%s type %s", fingerprint, key_type);
	SSHD_CORE::log_session_update_event(CR, ts, "AUTH_KEY_FINGERPRINT_2", s_data);

	# this is for the generation of the USER_CORE::auth_transaction_token token
	#  create a map for ses-key <-> fingerprint
	local t_key = SSHD_CORE::get_info_key(CR);
	event USER_CORE::auth_transaction_token(CR$uid, t_key, fingerprint);
	}

event bro_done()
	{
	#
	}
