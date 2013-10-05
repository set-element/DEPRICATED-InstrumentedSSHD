# 04/04/11: Scott Campbell
#
# Framework for converting local policy into analysis of behavior
#
# The idea is that the same events processed by core will also be processed here, except
#  that the local site policy will be audited (and possible enforced ehre).
#

@load sshd_core

module SSHD_POLICY;

export {

	redef enum Notice::Type += {
		SSHD_RemoteExecHostile,
		SSHD_Suspicous,
		SSHD_SuspicousThreshold,
		SSHD_Hostile,
		SSHD_BadKey,
		#
		SSHD_POL_InvalUser,
		SSHD_POL_AuthPassAtt,
		SSHD_POL_PassSkip,
		SSHD_POL_ChanPortOpen,
		SSHD_POL_ChanPortFwrd,
		SSHD_POL_ChanPostFwrd,
		SSHD_POL_ChanSetFwrd,
		SSHD_POL_Socks4,
		SSHD_POL_Socks5,
		SSHD_POL_SesInChanOpen,
		SSHD_POL_SesNew,
		SSHD_POL_DirTCPIP,
		SSHD_POL_TunInit,
		SSHD_POL_x11fwd,
	};
	
	######################################################################################
	# Events to alarm - A NOTICE will be made for each of these events if the appropriate
	#   conditions are met.
	# The large number of NOTICEs allows for per notice filtering and actions up to and
	#   including drop actions as wanted.  
	######################################################################################
	# default on - looking at session content as well as looking at remote exec 
	#  quantities
	global channel_data_client_notice = T &redef;
	global channel_data_server_notice = T &redef;
	global channel_notty_analysis_disable_notice = T &redef;
	global channel_notty_server_data_notice = T &redef;
	global channel_notty_client_data_notice = T &redef;
	global session_remote_do_exec_notice = T &redef;
	global session_remote_exec_no_pty_notice = T &redef;
	global session_remote_exec_pty_notice = T &redef;
	#
	global auth_invalid_user_notice = T &redef;
	global auth_pass_attempt_notice = F &redef;
	global channel_pass_skip_notice = T &redef;
	global channel_port_open_notice = F &redef;
	global channel_portfwd_req_notice = F &redef;
	global channel_post_fwd_listener_notice = F &redef;
	global channel_set_fwd_listener_notice = F &redef;
	global channel_socks4_notice = F &redef;
	global channel_socks5_notice = F &redef;
	global session_input_channel_open_notice = F &redef;
	global session_new_notice = F &redef;
	global session_request_direct_tcpip_notice = F &redef;
	global session_tun_init_notice = F &redef;
	global session_x11fwd_notice = F &redef;

	######################################################################################
	#  configuration: delinate individual commands that are interesting in terms
	#    of severity
	######################################################################################

	# suspicous commands 
	global notify_suspicous_command = T &redef;

	global suspicous_threshold: count = 5 &redef;
	global suspicous_command_list = 
		/^who/
		| /^rpcinfo/
		| /uname -a/
	&redef;

	# this set of commands should be alarmed on when executed
	#  remotely
	global alarm_remote_exec =
		/sh -i/
		| /bash -i/
	&redef;

	const user_white_list =
		/^billybob$/
	&redef;

	# Data formally from login.bro - this has been imported as a basic set with
	#  additional notes put in the local instance init file.  
	#
	const input_trouble = 
		  /rewt/
		| /eggdrop/
		| /(shell|xploit)_?code/
		| /execshell/
		| /cd[ \t]+\/dev\/[a-zA-Z]{3}/
		| />\/etc\/passwd/
		| /#define NOP.*0x/
		# test to see if these generate too much noise
		| /setuid\(0\)/
		| /setgid\(0\)/
		# look for shells being execed in a c-code sort of way
		| /execl\(\"\/bin\/sh\"\, \"\/bin\/sh\", NULL\)/
		# another test for signal/noise
		| /open\(\"\/proc\/ksyms\", \"r\"\)/
		# somewhat oldschool, but often old is tried before new ....
		| /open\(\"\/dev\/(mem|kmem|oldmem|shmem)/
		# it is quite handy that code writers tell us what they are doing ..
		| /[Ll][Ii][Nn][Uu][Xx][[:blank:]]*([Ll][Oo0][Cc][Aa][Ll]|[Kk][Ee][Rr][Nn][Aa][Ll]).*([Ee][Xx][Pp][Ll][Oo0][Ii][Tt]|[Pp][Rr][Ii][Vv][Ll][Ee][Gg][Ee]|[Rr][Oo0][Oo0][Tt])/
		# the old self-re-exec ...
		| /execl\(\"\/proc\/self\/exe\"/
		# this general interface form has become really common.  Thanks!
		| /(printf|print|fprintf|echo)[[:blank:]].*\[(\-|\+|\*|[Xx]|[:blank:]|!)[[:blank:]].*\]/
		# second half of above generalization.  Seriously, I really appreciate the standardization of interfaces!
		| /[[:blank:]]*\[(\-|\+|\*|[Xx]|[:blank:]|!)[[:blank:]]*\]([Aa][Bb][Uu][Ss][Ii][Nn][Gg]|[Ee][Xx][Pp][Ll][Oo0][Ii][Tt]|[Cc][Ll][Ee][Aa][Nn][Ii][Nn][Gg]|[Ee][Xx][Ie][Cc][Uu][Tt][Ii][Nn][Gg]|[Ff][Aa][Ii][Ll][Ee][Dd]|[Ll][Aa][Uu][Nn][Cc][Hh][Ii][Mn][Gg]|[Ll][Ii][Nn][Uu][Xx]|[Pp][Aa][Rr][Aa][Mm][Ee][Tt][Ee][Rr]|[Ss][Yy][Mm][Bb][Oo][Ll]|[Pp][Rr][Ii]Vv]|[Tt][Rr][Ii][Gg][Gg][Ee][Rr]|[Tt][O0o][O0o][Ll])/
		# words words words, probably too noisy
		| /[Ss][Hh][Ee3][Ll1][Ll1][Cc][Oo0[Dd][Ee]|[Pp][A@][Yy][Ll1][Oo0][Aa@][Dd]|[Ee][Xx][Pp][Ll1][Oo0][Ii][Tt]/
		# common more last year
		| /selinux_ops|dummy_security_ops|capability_ops/
		# words that I do not commonly find in scientific or benchmark code ...
		| /[Kk]3[Rr][Nn]3[Ll]|[Rr]3[Ll]3[Aa][Ss$]3|[Mm]3[Tt][Hh]34[Dd]|[Ll][Oo0][Oo0][Kk]1[Nn][Gg]|[Tt]4[Rr][Gg]3[Tt][Zz]|[Cc]0[Mm][Pp][Uu][Tt]3[Rr]|[Ss][Hh][Ee3][Ll1][Ll1][Cc][Oo0][Dd][Ee3]|[Bb][Ii1][Tt][Cc][Hh][Ee3][ZzSs$]/

	&redef;

	const output_trouble =
		  /^-r.s.*root.*\/bin\/(sh|csh|tcsh)/
		| /Jumping to address/
		| /(shell|xploit)_code/
		| /execshell/
		| /BOT_VERSION/
		| /(cd \/; uname -a; pwd; id)/
		| /[aA][dD][oO][rR][eE]/	# rootkit
		| /setuid\(0\)/
		| /setgid\(0\)/
		| /execl\(\"\/bin\/sh\"\, \"\/bin\/sh\", NULL\)/
		| /open\(\"\/proc\/ksyms\", \"r\"\)/
		| /open\(\"\/dev\/(mem|kmem|oldmem|shmem)/
		| /[Ll][Ii][Nn][Uu][Xx][[:blank:]]*([Ll][Oo0][Cc][Aa][Ll]|[Kk][Ee][Rr][Nn][Aa][Ll]).*([Ee][Xx][Pp][Ll][Oo0][Ii][Tt]|[Pp][Rr][Ii][Vv][Ll][Ee][Gg][Ee]|[Rr][Oo0][Oo0][Tt])/
		| /execl\(\"\/proc\/self\/exe\"/
		| /(printf|print|fprintf|echo)[[:blank:]].*\[(\-|\+|\*|[Xx]|[:blank:]|!)[[:blank:]].*\]/
		| /[[:blank:]]*\[(\-|\+|\*|[Xx]|[:blank:]|!)[[:blank:]]*\]([Aa][Bb][Uu][Ss][Ii][Nn][Gg]|[Ee][Xx][Pp][Ll][Oo0][Ii][Tt]|[Cc][Ll][Ee][Aa][Nn][Ii][Nn][Gg]|[Ee][Xx][Ie][Cc][Uu][Tt][Ii][Nn][Gg]|[Ff][Aa][Ii][Ll][Ee][Dd]|[Ll][Aa][Uu][Nn][Cc][Hh][Ii][Mn][Gg]|[Ll][Ii][Nn][Uu][Xx]|[Pp][Aa][Rr][Aa][Mm][Ee][Tt][Ee][Rr]|[Ss][Yy][Mm][Bb][Oo][Ll]|[Pp][Rr][Ii]Vv]|[Tt][Rr][Ii][Gg][Gg][Ee][Rr]|[Tt][O0o][O0o][Ll])/
		| /[Ss][Hh][Ee3][Ll1][Ll1][Cc][Oo0[Dd][Ee]|[Pp][Aa@][Yy][Ll1][Oo0][Aa@][Dd]|[Ee][Xx][Pp][Ll1][Oo0][Ii][Tt]/
		| /selinux_ops|dummy_security_ops|capability_ops/
		| /[Kk]3[Rr][Nn]3[Ll]|[Rr]3[Ll]3[Aa][Ss$]3|[Mm]3[Tt][Hh]34[Dd]|[Ll][Oo0][Oo0][Kk]1[Nn][Gg]|[Tt]4[Rr][Gg]3[Tt][Zz]|[Cc]0[Mm][Pp][Uu][Tt]3[Rr]|[Ss][Hh][Ee3][Ll1][Ll1][Cc][Oo0][Dd][Ee3]|[Bb][Ii1][Tt][Cc][Hh][Ee3][ZzSs$]/

	&redef;

	# lists of regular expressions which might trigger the hostile detect, but 
	#   are actually benign from this context.
	const input_trouble_whitelist  = /XXX/ &redef;

	const output_trouble_whitelist = /XXX/ &redef;
		

	global bad_key_list: set[string] &redef;

} # end export

######################################################################################
#  external values
######################################################################################

#redef notice_action_filters += {
#	[SSHD_RemoteExecHostile] = send_email_notice,
#	[SSHD_BadKey] = send_email_notice,
#};



######################################################################################
#  data structs and tables
######################################################################################
# 
# This section has been cleaned up and pointed at the core code to avoid synching issues
#

#########################################################################################
# functions
#########################################################################################

function parse_line(data: string, t: count) : set[string]
{
	# the data field contains some sort of hostile content.
	# we parse through it and return the set of offending commands 
	# if possible.  
	# this as been expanded to allow for multiple types of line parsing
	#
	# note that the whitelist test is run against the entire semicolin delim
	#  set since it is designed to deal with context
	#

	local return_set: set[string];
	local sc_element: count;
	local space_element: count;

	# look for multiple comands separated by ';' since a;b;c will have no strings
	local split_on_sc = split(data, /;/);

	for ( sc_element in split_on_sc ) {
		# now split ; separated commands up on space
		local split_on_space = split(split_on_sc[sc_element], / /);

		for ( space_element in split_on_space ) {

			# this section is a little gross ...
			if ( t == LINE_SUSPICOUS ) {

				if ( suspicous_command_list in split_on_space[space_element] && 
					split_on_space[space_element] !in return_set) {

		 			add return_set[ split_on_space[space_element] ];
					#print fmt("seen hostile command: %s", split_on_space[space_element]);
				}
			} # end LINE_SUSPICOUS

			if ( t == LINE_CLIENT )  {

				if ( (input_trouble in split_on_space[space_element]) && 
					(split_on_space[space_element] !in return_set) &&
					(input_trouble_whitelist !in split_on_sc[sc_element]) ) {

		 			add return_set[ split_on_space[space_element] ];
					#print fmt("seen hostile command: %s", split_on_space[space_element]);
				}
			} # end LINE_CLIENT

			if ( t == LINE_SERVER ) { 
		
				if ( (output_trouble in split_on_space[space_element]) && 
					(split_on_space[space_element] !in return_set) &&
					(output_trouble_whitelist !in split_on_sc[sc_element]) ) {

		 			add return_set[ split_on_space[space_element] ];
					#print fmt("seen hostile command: %s", split_on_space[space_element]);
				}
			} # end LINE_SERVER

		}
	} # end ; for sc_element loop

	return return_set;
}


function test_suspicous(data:string, CR: SSHD_CORE::client_record, channel:count, sid:string, cid:count) : int
	{
	# Test URI encoded data string for suspicous commands
	# Note that the data value will be returned to the original byte
	#   values before analysis so that byte values can be test against.  

	local ret= 0; # default return value

	# first look at the entire string to see if it conains any of the 
	#  suspicous expressions
	if ( suspicous_command_list in data ) {
	
		# Now that we know that a value exists that we are intereted in,
		#  spend the additional effort to determine the value.
		# Note that there might be more than one value per line
		local s_set: set[string];
		local s_set_element: string;

		# parse_linr() defined above - this is doing the real work of detection
		s_set = parse_line(data, LINE_SUSPICOUS);	

		# The set 's_set' contains (one/multiple) commands which have been identified as suspicous.
		# Go through them and make sure that the current CR has not counted them already
		for ( s_set_element in s_set ) {

			if ( s_set_element !in CR$s_commands ) {
				add CR$s_commands[s_set_element];
				++ret;

				++CR$suspicous_count;

				if ( (notify_suspicous_command) && (CR$suspicous_count <= suspicous_threshold) ) {
	
					NOTICE([$note=SSHD_Suspicous,
						$msg=fmt("#%s %s %s %s %s @ %s -> %s:%s command: %s",
						CR$client_tag, channel, sid, cid, CR$uid,
						CR$id$orig_h, CR$id$resp_h, 
						CR$id$resp_p, s_set_element)]);
					}

				# at suspicous_threshold, append commands together
				if ( CR$suspicous_count == suspicous_threshold ) {

					local t_s: string = " ";
					local r_s: string = " ";

					for ( t_s in CR$s_commands ) {
						r_s = fmt("%s %s", r_s, t_s);
					}

					NOTICE([$note=SSHD_SuspicousThreshold,
						$msg=fmt("#%s %s %s %s %s @ %s -> %s %s:%s {%s}",
						CR$client_tag, channel, sid, cid, CR$uid, 
						CR$id$orig_h, sid, CR$id$resp_h, 
						CR$id$resp_p, r_s)]);
				}
			} # end  s_set_element !in CR$s_commands

		} #end for s_set
	}

	return ret; # return value = count of new suspicous elements
}

# Look for hostile strings in remote exec values
# 
function test_remote_exec(data: string, CR: SSHD_CORE::client_record, sid:string, cid:count) : int
	{
	local ret= 0; # default return value

	if ( alarm_remote_exec in data ) {
	
		#
		NOTICE([$note=SSHD_RemoteExecHostile,
		$msg=fmt("#%s - %s %s %s @ %s -> %s:%s command: %s",
		CR$client_tag, sid, cid, CR$uid, 
		CR$id$orig_h, CR$id$resp_h, 
		CR$id$resp_p, data)]);
			
		ret = 1;
		}
		
	return ret;
	}

function test_hostile_client(data:string, CR: SSHD_CORE::client_record, channel:count, sid:string, cid:count) : int
	{
	local ret= 0; # default return value

	if ( input_trouble in data ) {

		# now extract the offending command(s)
		local s_set: set[string];
		local s_set_element: string = " ";

		s_set = parse_line(data, LINE_CLIENT);	

		# If data contains a locally whitelisted element, then
		#  the return vlue here might be empty.  If so, then
		#  bail
		if ( |s_set| == 0 )
			return ret;

		local ret_str: string = " ";

		# glue the mess together
		for ( s_set_element in s_set ) {
			ret_str = fmt("%s %s", ret_str, s_set_element);
		}

		# XXX get test for channel non-exist

		# now make sure the mess is safe to print in the notice
		NOTICE([$note=SSHD_Hostile,
			$msg=fmt("#%s %s %s %s %s @ %s -> %s:%s client output:%s [%s]",
				CR$client_tag, CR$channel_type[channel], sid, cid, 
				CR$uid, CR$id$orig_h, CR$id$resp_h, CR$id$resp_p, 
				str_shell_escape(data), str_shell_escape(ret_str) )]);

				
		ret = 1;
		}
		
	return ret;
	
	}

function test_hostile_server(data:string, CR: SSHD_CORE::client_record, channel:count, sid:string, cid:count) : int
	{
	local ret= 0; # default return value

	if ( output_trouble in data ) {

		# now extract the offending command(s)
		local s_set: set[string];
		local s_set_element: string = " ";

		s_set = parse_line(data, LINE_SERVER);	

		# if data contains a locally whitelisted element, then
		#  the return vlue here might be empty.  If so, then
		#  bail
		if ( |s_set| == 0 )
			return ret;

		local ret_str: string = " ";

		# glue the mess together
		for ( s_set_element in s_set ) {
			ret_str = fmt("%s %s", ret_str, s_set_element);
		}
	
		NOTICE([$note=SSHD_Hostile,
			$msg=fmt("#%s %s %s %s %s @ %s -> %s:%s server output: %s [%s]",
				CR$client_tag, CR$channel_type[channel], sid, cid, CR$uid, 
				CR$id$orig_h, CR$id$resp_h, CR$id$resp_p,  
				str_shell_escape(data), str_shell_escape(ret_str) )]);
				
		ret = 1;
		}
		
	return ret;
	
	}

#########################################################################################
# events
#########################################################################################
event auth_invalid_user_3(ts: time, version: string, sid: string, cid: count, uid: string)
{
	if ( auth_invalid_user_notice ) {
		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_InvalUser,
			$msg=fmt("#%s %s @ %s -> %s:%s", CR$client_tag, uid, 
				CR$id$orig_h, CR$id$resp_h, CR$id$resp_p )]);
	}
}

event auth_key_fingerprint_3(ts: time, version: string, sid: string, cid: count, fingerprint: string, key_type: string)
{
	local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);
	
	if ( fingerprint in bad_key_list ) {

		NOTICE([$note=SSHD_BadKey,
			$msg=fmt("#%s 0 %s %s %s @ %s -> %s:%s %s %s %s",
				CR$client_tag, sid, cid, CR$uid,
				CR$id$orig_h, sid, CR$id$resp_h,
				CR$id$resp_p, key_type, fingerprint)]);
			
		print SSHD_CORE::sshd_log, 
			fmt("%.6f #%s - %s %s SSH_KNOWN_BAD_KEY %s type %s", 
				ts, CR$client_tag, sid, cid, fingerprint, key_type);
	}

}

event auth_pass_attempt_3(ts: time, version: string, sid: string, cid: count, uid: string, password: string)
{
	if ( auth_pass_attempt_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_AuthPassAtt,
			$msg=fmt("#%s %s @ %s:%s -> %s:%s", CR$client_tag, uid, password,
				CR$id$orig_h, CR$id$resp_h, CR$id$resp_p )]);
	}
}

event channel_data_client_3(ts: time, version: string, sid: string, cid: count, channel:count, data:string)
{
	if ( channel_data_client_notice ) {

		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		if ( channel !in CR$channel_type )
			{
				CR$channel_type[channel] = "unknown";
			}

		# run client data through analyzer for both suspicous and hostile content
		test_suspicous(data, CR, channel, sid, cid);
		test_hostile_client(data, CR, channel, sid, cid);
	}

}

event channel_data_server_3(ts: time, version: string, sid: string, cid: count, channel: count, data: string)
{
	if ( channel_data_server_notice ) {

		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		if ( channel !in CR$channel_type )
			{
				CR$channel_type[channel] = "unknown";
			}

		# run client data through analyzer for both suspicous and hostile content
		test_suspicous(data, CR, channel, sid, cid);
		test_hostile_server(data, CR, channel, sid, cid);
	}

}


event channel_notty_client_data_3(ts: time, version: string, sid: string, cid: count, channel: count, data: string)
{
	if ( channel_notty_client_data_notice ) {

		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		if ( channel !in CR$channel_type )
			{
				CR$channel_type[channel] = "unknown";
			}

		# run client data through analyzer for both suspicous and hostile content
		test_suspicous(data, CR, channel, sid, cid);
		test_hostile_client(data, CR, channel, sid, cid);
	}
}

event channel_notty_server_data_3(ts: time, version: string, sid: string, cid: count, channel: count, data: string)
{
	if ( channel_notty_server_data_notice ) {

		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		if ( channel !in CR$channel_type )
			{
				CR$channel_type[channel] = "unknown";
			}

		# run client data through analyzer for both suspicous and hostile content
		test_suspicous(data, CR, channel, sid, cid);
		test_hostile_server(data, CR, channel, sid, cid);
	}
}

event channel_pass_skip_3(ts: time, version: string, sid: string, cid: count, channel: count)
{
	if ( channel_pass_skip_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_PassSkip,
			$msg=fmt("#%s %s @ %s:%s", CR$client_tag, CR$uid,
				CR$id$resp_h, CR$id$resp_p )]);
	}

}

event channel_port_open_3(ts: time, version: string, sid: string, cid: count, channel: count, rtype: string, l_port: port, path: string, h_port: port, rem_host: string, rem_port: port)
{
	if ( channel_port_open_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_ChanPortOpen,
			$msg=fmt("#%s listen port %s for %s %s:%s -> %s:%s",
				CR$client_tag, rtype, l_port, rem_host, rem_port, path, h_port)]);
	}

}

event channel_portfwd_req_3(ts: time, version: string, sid: string, cid: count, channel:count, host: string, fwd_port: count)
{
	if ( channel_portfwd_req_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_ChanPortFwrd,
			$msg=fmt("#%s %s:%s", CR$client_tag, host, fwd_port)]);
	}
}

event channel_post_fwd_listener_3(ts: time, version: string, sid: string, cid: count, channel: count, l_port: port, path: string, h_port: port, rtype: string)
{
	if ( channel_post_fwd_listener_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_ChanPostFwrd,
			$msg=fmt("#%s %s %s -> %s:%s", 
				CR$client_tag, rtype, l_port, path, h_port)]);
	}
}

event channel_set_fwd_listener_3(ts: time, version: string, sid: string, cid: count, channel: count, c_type: count, wildcard: count, forward_host: string, l_port: port, h_port: port)
{
	if ( channel_set_fwd_listener_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_ChanSetFwrd,
			$msg=fmt("#%s wc:%s %s -> %s:%s", 
				CR$client_tag, wildcard, l_port, forward_host, h_port)]);
	}
}

event channel_socks4_3(ts: time, version: string, sid: string, cid: count, channel: count, path: string, h_port: port, command: count, username: string)
{
	if ( channel_socks4_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_Socks4,
			$msg=fmt("#%s command: %s socks4 to %s @ %s:%s", 
				CR$client_tag, command, username, path, h_port)]);
	}
}

event channel_socks5_3(ts: time, version: string, sid: string, cid: count, channel: count, path: string, h_port: port, command: count)
{
	if ( channel_socks5_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_Socks5,
			$msg=fmt("#%s command: %s[%s] socks5 to %s:%s",
				CR$client_tag, socks5_header_types[command], command, path, h_port)]);
	}
}

event session_input_channel_open_3(ts: time, version: string, sid: string, cid: count, tpe: count, ctype: string, rchan: int, rwindow: int, rmaxpack: int)
{
	if ( session_input_channel_open_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_SesInChanOpen,
			$msg=fmt("#%s %s ctype %s rchan %d win %d max %d",
				CR$client_tag,CR$channel_type[int_to_count(rchan)], 
				ctype, rchan, rwindow, rmaxpack)]);
	}
}

event session_new_3(ts: time, version: string, sid: string, cid: count, pid: int, ver: string)
{
	if ( session_new_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_SesNew,
			$msg=fmt("#%s %s", CR$client_tag, ver)]);
	}
}

event session_remote_do_exec_3(ts: time, version: string, sid: string, cid: count, channel: count, ppid: count, command: string)
{
	if ( session_remote_do_exec_notice ) {
		# This is called to fork and execute a command.  If another command is
		#  to be forced, execute that instead.

		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		#function test_remote_exec(data: string, CR: SSHD_CORE::client_record, sid:string, cid:count) : int
		test_remote_exec(command, CR, sid, cid);
	}

}

event session_remote_exec_no_pty_3(ts: time, version: string, sid: string, cid: count, channel: count, ppid: count, command: string)
{
	if ( session_remote_exec_no_pty_notice ) {
		# This is called to fork and execute a command when we have no tty.  This
		#  will call do_child from the child, and server_loop from the parent after
		#  setting up file descriptors and such.

		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		test_remote_exec(command, CR, sid, cid);
	}
}

event session_remote_exec_pty_3(ts: time, version: string, sid: string, cid: count, channel: count, ppid: count, command: string)
{
	if ( session_remote_exec_pty_notice ) {
		# This is called to fork and execute a command when we have a tty.  This
		#  will call do_child from the child, and server_loop from the parent after
		#  setting up file descriptors, controlling tty, updating wtmp, utmp,
		#  lastlog, and other such operations.

		local CR:SSHD_CORE::client_record = SSHD_CORE::test_cid(sid,cid);

		test_remote_exec(command, CR, sid, cid);
	}
}

event session_request_direct_tcpip_3(ts: time, version: string, sid: string, cid: count, channel: count, originator: string, orig_port: port, target: string, target_port: port, i: count)
{
	if ( session_request_direct_tcpip_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_DirTCPIP,
			$msg=fmt("#%s %s:%s -> %s:%s",
				CR$client_tag, originator, orig_port, target, target_port)]);
	}
}

event session_tun_init_3(ts: time, version: string, sid: string, cid: count, channel: count, mode: count)
{
	if ( session_tun_init_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_TunInit,
			$msg=fmt("#%s %s", CR$client_tag, tunnel_type[mode] )]);
	}
}

event session_x11fwd_3(ts: time, version: string, sid: string, cid: count, channel: count, display: string)
{
	if ( session_x11fwd_notice ) {
		local CR:SSHD_CORE::client_record =  SSHD_CORE::test_cid(sid,cid);

		NOTICE([$note=SSHD_POL_x11fwd,
			$msg=fmt("#%s %s", CR$client_tag, display)]);
	}
}

# events to modify the key list
#
# see the sshd_key_data.bro file for a bulk input example.
#
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
