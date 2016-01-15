# (uses listen.bro just to ensure input sources are more reliably fully-read).
#  This is a input file reader which looks at the data line and decides which event
#   to envoke based on the initial field.  It is big and gross and fragile which is not
#   exactly how they tell you to do this sort of thing...
#
#
@load base/protocols/ssh
@load frameworks/communication/listen
@load base/frameworks/input

module SSHD_IN_STREAM;

export {
	
	redef enum Notice::Type += {
		SSHD_INPUT_UnknownEvent,
		SSHD_INPUT_LowTransactionRate,
		};

	## table holding map between event name -> handling function
	const dispatcher: table[string] of function(_data: string): count &redef;
	## number of arguments - used to filter dirty data
	const argument_count: table[string] of vector of count &redef;

	## regx to test data types
	global kv_splitter: pattern = / / &redef;
	global count_match: pattern = /^[0-9]{1,16}$/;
	global port_match: pattern = /^[0-9]{1,5}\/(tcp|udp|icmp)$/;
	global time_match: pattern = /^[0-9]{9,10}.[0-9]{0,6}$/;

	# this pattern is used to take apart multi-line patterns that are stuck together
	# they tend to focus on just a few event types, so we try them for now
	global multi_match: pattern = /^notty_server_data |^channel_notty_server_data_3 |^channel_data_server_3 |^channel_notty_client_data_3 |^data_server |^notty_server_data_2 |^data_client |^data_server_2 /;
#
	global v16: vector of count = vector(2,3,4,5,6,7,8,9,10,11,12,13,14,15,16);
	global v2s: vector of count = vector(2,4,6);

	# location of input file
	const data_file = "/trace/sshd_logs/ssh_logging" &redef;
	# semiphore for in-fr restart
	global stop_sem = 0;

	# notify on unknown event?
	const notify_unknown_event = F;

	# track the transaction rate - notice on transition between low and high water rates
	const input_count_test = T &redef;
	const input_low_water:count = 10 &redef; 
	const input_high_water:count = 100 &redef; 
	const input_test_interval:interval = 60 sec &redef;
	# track input rate ( events/input_test_interval)
	global input_count: count = 1 &redef;
	global input_count_prev: count = 1 &redef;
	#  0=pre-init, 1=ok, 2=in low error
	global input_count_state: count = 0 &redef;

	}

type lineVals: record {
	d: string;
};

redef InputAscii::empty_field = "EMPTY";

## ----- functions ----- ##
#
# utility functions for converting string types in key=value form
#   to native values
#
function ssh_time(s: string) : time
	{
	# default return value is 0.00000 which is the error token
	local key_val = split1(s, /=/);
	local ret_val: time = double_to_time( to_double("0.000000"));

	if ( |key_val| == 2 ) {

		local mpr = match_pattern( key_val[2], time_match);

		if ( mpr$matched )
			ret_val = double_to_time( to_double(key_val[2] ));

		}

	return ret_val;
	}

function ssh_string(s: string) : string
	{
	# substitute '+' with a space
	local sub_s = subst_string( s, "+", " ");
	local key_val = split1(sub_s, /=/);
	local ret_str: string = " ";

	if ( |key_val| == 2 ) {
		ret_str = raw_unescape_URI( key_val[2] );
		# remove backspace characters
		ret_str = edit(ret_str, "\x08");
		ret_str = edit(ret_str, "\x7f");
		ret_str = gsub(ret_str, /\x0a/, "");
		ret_str = gsub(ret_str, /\x1b\x5b\x30\x30\x6d/, "");
		ret_str = gsub(ret_str, /\x1b\x5b./, "");

		ret_str = escape_string(ret_str);	
		
		}
	else {
		ret_str = "NULL";
		}

	return ret_str;
	}

function ssh_count(s: string) : count
	{
	#print fmt("ssh_count in: %s", s);
	local key_val = split1(s, /=/);
	local ret_val: count = 0;

	if ( |key_val| == 2 ) {

		local t_count = key_val[2];
		local mpr = match_pattern( t_count, count_match);

		if ( mpr$matched )
			ret_val =  to_count( t_count );
		else {
			#print fmt("COUNT PATTERN ERROR: %s", key_val[2]);
			}
		}

	return ret_val;
	}

function ssh_addr(s: string) : addr
	{
	local key_val = split1(s, /=/);
	local ret_val:addr = to_addr( "127.5.5.5");

	if ( |key_val| == 2 )
		ret_val = to_addr( key_val[2] );

	return ret_val;
	}

function ssh_port(s: string) : port
	{
	local key_val = split1(s, /=/);
	local ret_val = to_port("10/tcp");

	if ( |key_val| == 2 ) {
		# test to see if the "value" component is missing the protocol string
		local t_port = key_val[2];
		local p_pm = match_pattern( t_port, port_match );

		if ( p_pm$matched ) {
			ret_val = to_port(t_port);
			}	
		else {
			local c_pm = match_pattern( t_port, count_match );

			if ( c_pm$matched ) {
				t_port = fmt("%s/tcp", t_port);
				ret_val = to_port(t_port);
				}
			}
		}

	return ret_val;
	}

function ssh_int(s: string) : int
	{
	local key_val = split1(s, /=/);
	local ret_val:int = 0;

	if ( |key_val| == 2 )
		ret_val = to_int(key_val[2]);

	return ret_val;
	}

function dump_line_data(_data: string) : count
	{
	local ret = 0;
        local parts = split(_data, kv_splitter);
	local l_parts = |parts|;
	local ni: count = 2;
	local event_name = parts[1];

	# run through the arguments
	for ( ni in v16 ) {
		if ( ni <= l_parts ) {
			# convert to count
			local n = int_to_count(ni);
			# split type=value
			local key_val = split1(parts[n], /=/);
			#
			#print fmt("%s %s %s %s", n, parts[n], key_val[1], key_val[2]);
			}
		}

	}


function _auth_info_3(_data: string) : count
	{
	# event auth_info_3(ts: time, version: string, sid: string, cid: count, authmsg: string, uid: string, meth: string, s_addr: addr, s_port: port, r_addr: addr, r_port: port)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local authmsg = ssh_string( parts[6] );
	local uid = ssh_string( parts[7] );
	local meth = ssh_string ( parts[8] );
	local s_addr = ssh_addr( parts[9] );
	local s_port = ssh_port( parts[10] );
	local r_addr = ssh_addr( parts[11] );
	local r_port = ssh_port( parts[12] );

	event auth_info_3(ts,version,sid,cid,authmsg,uid,meth,s_addr,s_port,r_addr,r_port);

	return 0;
	}

function _sftp_process_readlink_3(_data: string) : count
	{
	#event sftp_process_readlink_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string) 

	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_readlink_3(ts,version,sid,cid,ppid,d);
	
	return 0;
	}

function _sftp_process_readlink_2(_data: string) : count
	{
	# event sftp_process_readlink(ts:time, sid:string, cid:count, data:string)

	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_readlink(ts,sid,cid,d);

	return 0;
	}

function _sftp_process_readlink(_data: string) : count
	{
	# event sftp_process_readlink(ts:time, sid:string, cid:count, data:string)

	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_readlink(ts,sid,cid,d);

	return 0;
	}

function _sftp_process_rename(_data: string) : count
	{
	# event sftp_process_rename(ts:time, sid:string, cid:count, old_name:string, new_name:string)

	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );
	local d2 = ssh_string( parts[8] );

	event sftp_process_rename(ts,sid,cid,d,d2);

	return 0;
	}

function _sftp_process_rename_2(_data: string) : count
	{
	# event sftp_process_rename(ts:time, sid:string, cid:count, old_name:string, new_name:string)

	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );
	local d2 = ssh_string( parts[8] );

	event sftp_process_rename(ts,sid,cid,d,d2);

	return 0;
	}
	
function _sftp_process_rename_3(_data: string) : count
	{
	# event sftp_process_rename_3(ts:time, version: string, sid:string, cid:count, ppid: int, old_name:string, new_name:string)

	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local d = ssh_string( parts[7] );
	local d2 = ssh_string( parts[8] );

	event sftp_process_rename_3(ts,version,sid,cid,ppid,d,d2);

	return 0;
	}

function _sftp_process_setstat_2(_data: string) : count
	{
	# event sftp_process_setstat(ts:time, sid:string, cid:count, data:string)

	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local i = ssh_int( parts[7] );
	local d = ssh_string( parts[8] );

	event sftp_process_setstat(ts,sid,cid,d);

	return 0;
	}
	
function _sftp_process_setstat_3(_data: string) : count
	{
	# event sftp_process_setstat_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)

	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local i = ssh_int( parts[7] );
	local d = ssh_string( parts[8] );

	event sftp_process_setstat_3(ts,version,sid,cid,ppid,d);

	return 0;
	}
	
function _auth_key_fingerprint_3(_data: string) : count
	{
	# event auth_key_fingerprint_3(ts: time, version: string, sid: string, cid: count, fingerprint: string, key_type: string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local fingerprint = ssh_string( parts[6] );
	local key_type = ssh_string( parts[7] );

	event auth_key_fingerprint_3(ts,version,sid,cid,fingerprint,key_type);

	return 0;
	}

function _auth_ok(_data: string) : count
	{
	# event auth_ok(ts:time, sid:string, uid:string, authtype:string, s_addr: addr, s_port: port, r_addr: addr, r_port: port, cid: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local serv_interfaces = ssh_string( parts[4] );
	local sid = ssh_string( parts[5] );
	local uid = ssh_string( parts[6] );
	local authtype = ssh_string( parts[7] );
	local s_addr = ssh_addr( parts[8] );
	local s_port = ssh_port( parts[9] );
	local r_addr = ssh_addr( parts[10] );
	local r_port = ssh_port( parts[11] );
	local cid = ssh_count( parts[12] );

	event auth_ok_2(ts,version,serv_interfaces,sid,uid,authtype,s_addr,s_port,r_addr,r_port,cid);

	return 0;
	}

function _auth_ok_2(_data: string) : count
	{
	# event auth_ok_2(ts:time, version: string, serv_interfaces: string, sid:string, uid:string, authtype:string, s_addr: addr, s_port: port, r_addr: addr, r_port: port, cid: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local serv_interfaces = ssh_string( parts[4] );
	local sid = ssh_string( parts[5] );
	local uid = ssh_string( parts[6] );
	local authtype = ssh_string( parts[7] );
	local s_addr = ssh_addr( parts[8] );
	local s_port = ssh_port( parts[9] );
	local r_addr = ssh_addr( parts[10] );
	local r_port = ssh_port( parts[11] );
	local cid = ssh_count( parts[12] );

	event auth_ok_2(ts,version,serv_interfaces,sid,uid,authtype,s_addr,s_port,r_addr,r_port,cid);
	return 0;
	}

function _channel_data_client_3(_data: string) : count
	{
	# event channel_data_client_3(ts: time, version: string, sid: string, cid: count, channel:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event channel_data_client_3(ts,version,sid,cid,channel,d);
	return 0;
	}

function _channel_data_server_3(_data: string) : count
	{
	# event channel_data_server_3(ts: time, version: string, sid: string, cid: count, channel: count, _data: string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event channel_data_server_3(ts,version,sid,cid,channel,d);
	return 0;
	}

function _data_server_sum(_data: string) : count
	{
	# data_server_sum time=1342001137.222595 uristring=4549_cvrsvc01_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.1.64.5+128.55.56.5+128.
	# 55.69.224+128.55.33.224+ count=441292721 count=0 count=11123
	# data_server_sum(ts: time, sid: string, version: string, serv_interfaces: string,cid: count, channel: count, bytes_skip: count)
	# Q: last set in order ??
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local channel = ssh_count( parts[7] );
	local bytes_skip = ssh_count( parts[8] );

	event data_server_sum(ts,sid,version,serv_interfaces,cid,channel,bytes_skip);

	return 0;	
	}

function _data_server_sum_2(_data: string) : count
	{
	# data_server_sum time=1342001137.222595 uristring=4549_cvrsvc01_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.1.64.5+128.55.56.5+128.
	# 55.69.224+128.55.33.224+ count=441292721 count=0 count=11123
	# data_server_sum(ts: time, sid: string, version: string, serv_interfaces: string,cid: count, channel: count, bytes_skip: count)
	# Q: last set in order ??
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local channel = ssh_count( parts[7] );
	local bytes_skip = ssh_count( parts[8] );

	event data_server_sum_2(ts,sid,version,serv_interfaces,cid,channel,bytes_skip);

	return 0;	
	}

function _channel_data_server_sum_3(_data: string) : count
	{
	# event channel_data_server_sum_3(ts: time, version: string, sid: string, cid: count, channel: count, bytes_skip: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local bytes_skip = ssh_count( parts[7] );

	event channel_data_server_sum_3(ts,version,sid,cid,channel,bytes_skip);
	return 0;
	}

function _channel_exit(_data: string) : count
	{
	#print fmt("skipping _channel_exit %s", _data);
	return 0;
	}

function _channel_exit_2(_data: string) : count
	{
	# 
	#print fmt("skipping _channel_exit_2 %s", _data);
	return 0;
	}

function _channel_free_3(_data: string) : count
	{
	# event channel_free_3(ts: time, version: string, sid: string, cid: count,channel: count, name: string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local name = ssh_string( parts[7] );

	event channel_free_3(ts,version,sid,cid,channel,name);

	return 0;
	}

function _channel_new_3(_data: string) : count
	{
	# event channel_new_3(ts: time, version: string, sid: string, cid: count, found: count, ctype: count, name: string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local found = ssh_count( parts[6] );
	local ctype = ssh_count( parts[7] );
	local name = ssh_string( parts[8] );

	event channel_new_3(ts,version,sid,cid,found,ctype,name);

	return 0;
	}

function _channel_notty_analysis_disable_3(_data: string) : count
	{
	# event channel_notty_analysis_disable_3(ts: time, version: string, sid: string, cid: count, channel: count, byte_skip: int, byte_sent: int)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = 0;
	local byte_skip: int;
	local byte_sent: int;

	if ( |parts| == 8 ) {
		channel = ssh_count( parts[6] );
		byte_skip = ssh_int( parts[7] );
		byte_sent = ssh_int( parts[8] );
		}
	else {
		byte_skip = ssh_int( parts[6] );
		byte_sent = ssh_int( parts[7] );
		}
		
	event channel_notty_analysis_disable_3(ts,version,sid,cid,channel,byte_skip,byte_sent);

	return 0;
	}

function _channel_notty_client_data_3(_data: string) : count
	{
	# event channel_notty_client_data_3(ts: time, version: string, sid: string, cid: count, channel: count, _data: string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event channel_notty_client_data_3(ts,version,sid,cid,channel,d);

	return 0;
	}

function _channel_notty_server_data_3(_data: string) : count
	{
	# event channel_notty_server_data_3(ts: time, version: string, sid: string, cid: count, channel: count, _data: string)
	local parts = split(_data, kv_splitter);
	local l_parts = |parts|;

	local event_name = parts[1];
	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event channel_notty_server_data_3(ts,version,sid,cid,channel,d);
	return 0;
	}

function _data_client(_data: string) : count
	{
	# event data_client(ts:time, sid:string, cid:count, channel:count, _data:string)
	# data_client time=1342000801.342046 uristring=8247_hopper08_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.77.1.9+128.55.68.39+128.55.34.73+10.10.10.207+10.10.30.207+10.10.20.208+ count=627016360 count=0 uristring=p%7Fcd+C%09
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local channel = ssh_count( parts[7] );
	local d = ssh_string( parts[8] );

	event data_client_2(ts,sid,version,serv_interfaces,cid,channel,d);

	return 0;
	}

function _data_client_2(_data: string) : count
	{
	# event data_client_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local serv_interfaces = ssh_string( parts[4] );
	local sid = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local channel = ssh_count( parts[7] );
	local d = ssh_string( parts[8] );

	event data_client_2(ts,version,serv_interfaces,sid,cid,channel,d);

	return 0;
	}

function _data_server(_data: string) : count
	{
	# event data_server(ts:time, sid:string, cid:count, channel:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local serv_interfaces = ssh_string( parts[4] );
	local sid = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local channel = ssh_count( parts[7] );
	local d = ssh_string( parts[8] );

	event data_server_2(ts,version,serv_interfaces,sid,cid,channel,d);

	return 0;
	}

function _data_server_2(_data: string) : count
	{
	# event data_server_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local serv_interfaces = ssh_string( parts[4] );
	local sid = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local channel = ssh_count( parts[7] );
	local d = ssh_string( parts[8] );

	event data_server_2(ts,version,serv_interfaces,sid,cid,channel,d);

	return 0;
	}

function data_server_sum(_data: string) : count
	{
	return 0;
	}

function data_server_sum_2(_data: string) : count
	{
	# 
	return 0;
	}

function _new_channel_session(_data: string) : count
	{
	# event new_channel_session(ts:time, sid:string, channel:count, channel_type:string, cid:count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local serv_interfaces = ssh_string( parts[4] );
	local sid = ssh_string( parts[5] );
	local channel = ssh_count( parts[6] );
	local channel_type = ssh_string( parts[7] );
	local cid = ssh_count( parts[8] );

	event new_channel_session_2(ts,version,serv_interfaces,sid,channel,channel_type,cid);

	return 0;
	}

function _new_channel_session_2(_data: string) : count
	{
	# event new_channel_session_2(ts:time, version: string, serv_interfaces: string, sid:string, channel:count, channel_type:string, cid:count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local serv_interfaces = ssh_string( parts[4] );
	local sid = ssh_string( parts[5] );
	local channel = ssh_count( parts[6] );
	local channel_type = ssh_string( parts[7] );
	local cid = ssh_count( parts[8] );

	event new_channel_session_2(ts,version,serv_interfaces,sid,channel,channel_type,cid);

	return 0;
	}

function _new_session(_data: string) : count
	{
	# event new_session(ts:time, sid:string, version:string, cid:count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local ver = ssh_string( parts[6] );
	local cid = ssh_count( parts[7] );

	event new_session_2(ts,version,serv_interfaces,sid,ver,cid);

	return 0;
	}

function _new_session_2(_data: string) : count
	{
	# event new_session_2(ts:time, version: string, serv_interfaces: string, sid:string, ver:string, cid:count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local ver = ssh_string( parts[6] );
	local cid = ssh_count( parts[7] );

	event new_session_2(ts,version,serv_interfaces,sid,ver,cid);

	return 0;
	}

function _notty_analysis_disable(_data: string) : count
	{
	# event notty_analysis_disable(ts:time, sid:string, cid:count, byte_skip: count, byte_allow: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local byte_skip = ssh_int( parts[7] );
	local byte_allow = ssh_int( parts[8] );

	event notty_analysis_disable_2(ts,version,serv_interfaces,sid,cid,byte_skip,byte_allow);

	return 0;
	}

function _notty_analysis_disable_2(_data: string) : count
	{
	# event notty_analysis_disable_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, byte_skip: int, byte_allow: int)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local byte_skip = ssh_int( parts[7] );
	local byte_allow = ssh_int( parts[8] );

	event notty_analysis_disable_2(ts,version,serv_interfaces,sid,cid,byte_skip,byte_allow);

	return 0;
	}

function _notty_client_data(_data: string) : count
	{
	# event notty_client_data(ts:time, sid:string, cid:count, channel:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local channel = ssh_count( parts[7] );
	local d = ssh_string( parts[8] );

	event notty_client_data_2(ts,version,serv_interfaces,sid,cid,channel,d);
	
	return 0;
	}

function _notty_client_data_2(_data: string) : count
	{
	# event notty_client_data_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local channel = ssh_count( parts[7] );
	local d = ssh_string( parts[8] );

	event notty_client_data_2(ts,version,serv_interfaces,sid,cid,channel,d);

	return 0;
	}

function _notty_server_data(_data: string) : count
	{
	# event notty_server_data(ts:time, sid:string, cid:count, channel:count, _data:string)
	# notty_server_data time=1354513238.109957 uristring=32095_nid06135_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.128.24.40+10.10.20.101+ count=979185324 count=0
	#  uristring=XXRETCODE:0
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local channel = ssh_count( parts[7] );
	local d = ssh_string( parts[8] );

	event notty_server_data_2(ts,version,serv_interfaces,sid,cid,channel,d);

	return 0;
	}

function _notty_server_data_2(_data: string) : count
	{
	# event notty_server_data_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, channel:count, _data:string)
	# notty_server_data_2 time=1354513239.716295 uristring=4436_dtn01_22 uristring=NMOD_2.11 uristring=127.0.0.1+10.55.46.155+128.55.32.199+128.55.80.35+ count=9195
	# 55488 count=0 uristring=220+dtn01.nersc.gov+GridFTP+Server+3.33+(gcc64dbg,+1305148829-80)+%5BGlobus+Toolkit+5.0.4%5D+ready
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local channel = ssh_count( parts[7] );
	local d = ssh_string( parts[8] );

	event notty_server_data_2(ts,version,serv_interfaces,sid,cid,channel,d);

	return 0;
	}

function _server_heartbeat(_data: string) : count
	{
	return 0;
	# event server_heartbeat(ts: time, sid: string, dt: count)
	# server_heartbeat time=1342000801.940728 uristring=4582_cvrsvc09_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.1.64.13+128.55.56.13+128.55.69.232+128.55.33.232+ count=0
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local dt = ssh_count( parts[6] );

	#print "skipping event server_heartbeat(ts,sid,dt)";
	}

function _server_heartbeat_2(_data: string) : count
	{
	return 0;

	# event server_heartbeat_2(ts: time, version: string, serv_interfaces: string, sid: string, dt: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local serv_interfaces = ssh_string( parts[4] );
	local sid = ssh_string( parts[5] );
	local dt = ssh_count( parts[6] );

	#print "skipping event server_heartbeat_2(ts,version,serv_interfaces,sid,dt)";

	#return 0;
	}

function _server_input_channel_open(_data: string) : count
	{
	#print fmt("skipping channel_exit %s", _data);
	return 0;
	}

function _server_input_channel_open_2(_data: string) : count
	{
	# no id'd event, see:
	#  server_input_channel_open_2 time=1342001102.115794 uristring=7340_dtn01_22 uristring=NMOD_2.11 uristring=127.0.0.1+10.55.46.155+128.55.32.199+128.55.80.35+ u ristring=session int=0 int=2097152 int=32768
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local s1 = ssh_string( parts[6] );
	local i1 = ssh_int( parts[7] );
	local i2 = ssh_int( parts[8] );
	local i3 = ssh_int( parts[9] );

	return 0;
	}

function _session_channel_request_3(_data: string) : count
	{
	# event session_channel_request_3(ts: time, version: string, sid: string, cid: count, pid: int, channel: count, rtype: string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local pid = ssh_int( parts[6] );
	local channel = ssh_count( parts[7] );
	local rtype = ssh_string( parts[8] );

	event session_channel_request_3(ts,version,sid,cid,pid,channel,rtype);

	return 0;
	}

function _session_exit_3(_data: string) : count
	{
	# event session_exit_3(ts: time, version: string, sid: string, cid: count, channel: count, pid: count, ststus: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count ( parts[6] );
	local pid = ssh_count( parts[7] );
	local ststus = ssh_count( parts[8] );

	event session_exit_3(ts,version,sid,cid,channel,pid,ststus);

	return 0;
	}

function _session_input_channel_open_3(_data: string) : count
	{
	# event session_input_channel_open_3(ts: time, version: string, sid: string, cid: count, tpe: count, ctype: string, rchan: int, rwindow: int, rmaxpack: int)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local tpe = ssh_count( parts[6] );
	local ctype = ssh_string( parts[7] );
	local rchan = ssh_int( parts[8] );
	local rwindow = ssh_int( parts[9] );
	local rmaxpack = ssh_int( parts[10] );

	event session_input_channel_open_3(ts,version,sid,cid,tpe,ctype,rchan,rwindow,rmaxpack);

	return 0;
	}

function _session_new_3(_data: string) : count
	{
	# event session_new_3(ts: time, version: string, sid: string, cid: count, pid: int, ver: string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local pid = ssh_int( parts[6] );
	local ver = ssh_string( parts[7] );

	event session_new_3(ts,version,sid,cid,pid,ver);

	return 0;
	}

function _session_remote_do_exec_3(_data: string) : count
	{
	# event session_remote_do_exec_3(ts: time, version: string, sid: string, cid: count, channel: count, ppid: count, command: string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local ppid = ssh_count( parts[7] );
	local command = ssh_string( parts[8] );

	event session_remote_do_exec_3(ts,version,sid,cid,channel,ppid,command);

	return 0;
	}

function _session_remote_exec_no_pty_3(_data: string) : count
	{
	# event session_remote_exec_no_pty_3(ts: time, version: string, sid: string, cid: count, channel: count, ppid: count, command: string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local ppid = ssh_count( parts[7] );
	local command = ssh_string( parts[8] );

	event session_remote_exec_no_pty_3(ts,version,sid,cid,channel,ppid,command);
	return 0;
	}

function _session_request_direct_tcpip_3(_data: string) : count
	{
	# event session_request_direct_tcpip_3(ts: time, version: string, sid: string, cid: count, channel: count, originator: string, orig_port: port, target: string, target_port: port, i: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local originator = ssh_string( parts[7] );
	local orig_port = ssh_port( parts[8] );
	local target = ssh_string( parts[9] );
	local target_port = ssh_port( parts[10] );
	local i = ssh_count( parts[11] );

	event session_request_direct_tcpip_3(ts,version,sid,cid,channel,originator,orig_port,target,target_port,i);

	return 0;
	}

function _server_request_direct_tcpip(_data: string) : count
	{
	# event server_request_direct_tcpip(ts:time, sid:string, s_addr:string, s_port: port, r_addr: string, r_port: port, cid: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local s_addr = ssh_string( parts[6] );
	local s_port = ssh_port( parts[7] + "/tcp" );
	local r_addr = ssh_string( parts[8] );
	local r_port = ssh_port( parts[9] + "/tcp" );
	local cid = ssh_count( parts[10] );

	#event server_request_direct_tcpip(ts,sid,s_addr,s_port,r_addr,r_port,cid);

	return 0;
	}

function _server_request_direct_tcpip_2(_data: string) : count
	{
	# vent server_request_direct_tcpip_2(ts:time, version: string, serv_interfaces: string, sid:string, s_addr:string, s_port: port, r_addr: string, r_port: port, cid: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local serv_interfaces = ssh_string( parts[4] );
	local sid = ssh_string( parts[5] );
	local s_addr = ssh_string( parts[6] );
	local s_port = ssh_port( parts[7] );
	local r_addr = ssh_string( parts[8] );
	local r_port = ssh_port( parts[9] );
	local cid = ssh_count( parts[10] );

	event server_request_direct_tcpip_2(ts,version,serv_interfaces,sid,s_addr,s_port,r_addr,r_port,cid);

	return 0;
	}

function _session_x11fwd_3(_data: string) : count
	{
	# event session_x11fwd_3(ts: time, version: string, sid: string, cid: count, channel: count, display: string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local display = ssh_string( parts[7] );

	event session_x11fwd_3(ts,version,sid,cid,channel,display);

	return 0;
	}

function _sftp_process_close(_data: string) : count
	{
	# event sftp_process_close(ts:time, sid:string, cid:count, id: int, handle:int)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local id = ssh_int( parts[7] );
	local handle = ssh_int( parts[8] );

	event sftp_process_close(ts,sid,cid,id,handle);
	return 0;

	}

function _sftp_process_close_2(_data: string) : count
	{
	# event sftp_process_close(ts:time, sid:string, cid:count, id: int, handle:int)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local cid = ssh_count( parts[4] );
	local id = ssh_int( parts[5] );
	local handle = ssh_int( parts[6] );

	event sftp_process_close(ts,sid,cid,id,handle);
	return 0;

	}

function _sftp_process_close_3(_data: string) : count
	{
	# event sftp_process_close_3(ts:time, version: string, sid:string, cid:count, ppid: int, id: int, handle:int)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local id = ssh_int( parts[7] );
	local handle = ssh_int( parts[8] );

	event sftp_process_close_3(ts,version,sid,cid,ppid,id,handle);
	return 0;

	}

function _sftp_process_do_stat(_data: string) : count
	{
	# event sftp_process_do_stat(ts:time, sid:string, cid:count, _data:string)
	# event sftp_process_do_stat(ts:time, sid:string, version: string, cid:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_do_stat(ts,sid,version,cid,d);

	return 0;
	}

function _sftp_process_do_stat_2(_data: string) : count
	{
	# event sftp_process_do_stat(ts:time, sid:string, cid:count, _data:string)
	# event sftp_process_do_stat(ts:time, sid:string, version: string, cid:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_do_stat(ts,sid,version,cid,d);

	return 0;
	}

function _sftp_process_do_stat_3(_data: string) : count
	{
	# event sftp_process_do_stat_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_do_stat_3(ts,version,sid,cid,ppid,d);

	return 0;
	}

function _sftp_process_fsetstat(_data: string) : count
	{
	# event sftp_process_fsetstat(ts:time, sid:string, cid:count, _data:string)
	# sftp_process_fsetstat time=1342724316.473862 uristring=32470_cvrsvc02_22 uristring=NMOD_2.9 
	#  uristring=127.0.0.1+10.1.64.6+128.55.56.6+128.55.69.225+128.55.33.225+ 
	#  count=0 int=185 uristring=/global/u2/b/bnlcat/work/TiO2/RuTi_formate/RuTi_formate_06.msi
	# 
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local ppid = ssh_int( parts[7] );
	local d = ssh_string( parts[8] );

	event sftp_process_fsetstat(ts,sid,cid,d);

	return 0;
	}

function _sftp_process_fsetstat_3(_data: string) : count
	{
	# event sftp_process_mkdir_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string) 
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_fsetstat_3(ts,version,sid,cid,ppid,d);

	return 0;
	}

function _sftp_process_fstat(_data: string) : count
	{
	# event sftp_process_fstat(ts:time, sid:string, cid:count, data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_fstat(ts,sid,cid,d);

	return 0;
	}

function _sftp_process_fstat_3(_data: string) : count
	{
	return 0;
	# event sftp_process_fstat_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local i = ssh_int( parts[7] );
	local d = ssh_string( parts[8] );

	# for the time being I am removing this and opening a ticket on the isshd side event call
	#event sftp_process_fstat_3(ts,version,sid,cid,ppid,d);

	return 0;
	}

function _sftp_process_init(_data: string) : count
	{
	# sftp_process_init(ts:time, sid:string, version:string, serv_interfaces:string, cid:count, uid:string, a:addr)
	# sftp_process_init time=1350046754.477520 uristring=5854_cvrsvc01_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.1.64.5+128.55.56.5+128.55.69.224+128.55.33.224+ count=0 uristring=yiwang62 addr=128.118.156.18
	# sftp_process_init time=1350046754.499153 uristring=5854_cvrsvc01_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.1.64.5+128.55.56.5+128.55.69.224+128.55.33.224+ count=0 int=3
	#
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );

	local uid: string = "HOLDING";
	local a: addr = ssh_addr("addr=127.0.0.1");

	if ( |parts| > 7 ) {
		uid = ssh_string( parts[7] );
		a = ssh_addr( parts[8] );
		}

	event sftp_process_init(ts,sid,version,serv_interfaces,cid,uid,a);

	return 0;
	}

function _sftp_process_init_3(_data: string) : count
	{
	# event sftp_process_init_3(ts:time, version: string, sid:string, cid:count, ppid: int, vsn: string, caddr: addr)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local vsn: string;
	local caddr: addr;

	if ( |parts| == 8 ) {
		vsn = ssh_string( parts[7] );
		caddr = ssh_addr( parts[8] );
		}
	else {
		vsn = ssh_string( "NAME" );
		caddr = ssh_addr( "127.10.10.10" );
		}

	event sftp_process_init_3(ts,version,sid,cid,ppid,vsn,caddr);

	return 0;
	}

function _sftp_process_open(_data: string) : count
	{
	# event sftp_process_open(ts:time, sid:string, cid:count, _data:string)
	# sftp_process_open time=1342723860.9219 uristring=11093_cvrsvc01_22 uristring=NMOD_2.9 uristring=127.0.0.1+10.1.64.5+128.55.56.5+128.55.69.224+128.55.33.224+ count=0 uristring=/global/u2/a/amkessel/kdtree/cpu_prune/cpu_prune.cpp
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_open(ts,sid,cid,d);

	return 0;
	}

function _sftp_process_open_3(_data: string) : count
	{
	# event sftp_process_open_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_open_3(ts,version,sid,cid,ppid,d);

	return 0;
	}

function _sftp_process_opendir(_data: string) : count
	{
	# event sftp_process_opendir(ts:time, sid:string, cid:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_opendir(ts,sid,cid,d);

	return 0;
	}

function _sftp_process_opendir_2(_data: string) : count
	{
	# event sftp_process_opendir(ts:time, sid:string, cid:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_opendir(ts,sid,cid,d);

	return 0;
	}

function _sftp_process_opendir_3(_data: string) : count
	{
	# event sftp_process_opendir(ts:time, sid:string, cid:count, _data:string)
	# sftp_process_opendir_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_opendir_3(ts,version,sid,cid,ppid,d);

	return 0;
	}

function _sftp_process_readdir(_data: string) : count
	{
	# event sftp_process_readdir(ts:time, sid:string, cid:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_readdir(ts,sid,cid,d);

	return 0;
	}

function _sftp_process_readdir_2(_data: string) : count
	{
	# event sftp_process_readdir_2(ts:time, sid:string, cid:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_readdir(ts,sid,cid,d);

	return 0;
	}

function _sftp_process_readdir_3(_data: string) : count
	{
	# event sftp_process_readdir_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_readdir_3(ts,version,sid,cid,ppid,d);

	return 0;
	}

function _sftp_process_realpath(_data: string) : count
	{
	# event sftp_process_realpath(ts:time, sid:string, cid:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_realpath(ts,sid,cid,d);

	return 0;
	}

function _sftp_process_realpath_3(_data: string) : count
	{
	# event event sftp_process_realpath_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_realpath_3(ts,version,sid,cid,ppid,d);

	return 0;
	}

function _sftp_process_remove(_data: string) : count
	{
	# event sftp_process_remove(ts:time, sid:string, cid:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );
	
	event sftp_process_remove(ts,sid,cid,d);

	return 0;
	}

function _ssh_connection_end(_data: string) : count
	{
	# event ssh_connection_end(ts:time, sid:string, s_addr:addr, s_port:port, r_addr:addr, r_port:port, cid:count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local serv_interfaces = ssh_string( parts[4] );
	local sid = ssh_string( parts[5] );
	local s_addr = ssh_addr( parts[6] );
	local s_port = ssh_port( parts[7] );
	local r_addr = ssh_addr( parts[8] );
	local r_port = ssh_port( parts[9] );
	local cid = ssh_count( parts[10] );

	event ssh_connection_end_2(ts,version,serv_interfaces,sid,s_addr,s_port,r_addr,r_port,cid);

	return 0;
	}

function _ssh_connection_end_2(_data: string) : count
	{
	# event ssh_connection_end_2(ts:time, version: string, serv_interfaces: string, sid:string, s_addr:addr, s_port:port, r_addr:addr, r_port:port, cid:count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local serv_interfaces = ssh_string( parts[4] );
	local sid = ssh_string( parts[5] );
	local s_addr = ssh_addr( parts[6] );
	local s_port = ssh_port( parts[7] );
	local r_addr = ssh_addr( parts[8] );
	local r_port = ssh_port( parts[9] );
	local cid = ssh_count( parts[10] );

	event ssh_connection_end_2(ts,version,serv_interfaces,sid,s_addr,s_port,r_addr,r_port,cid);

	return 0;
	}

function _ssh_connection_start(_data: string) : count
	{
	# this is stubbed out
	#return 0;

	# event ssh_connection_start(ts:time, version: string, serv_interfaces: string, sid:string, s_addr:addr, s_port:port, r_addr:addr, r_port:port, cid:count)
	# event ssh_connection_start(ts:time, sid:string, s_addr:addr, s_port:port, r_addr:addr, r_port:port, cid:count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	#local version = ssh_string( parts[3] );
	#local serv_interfaces = ssh_string( parts[4] );
	local sid = ssh_string( parts[5] );
	local s_addr = ssh_addr( parts[6] );
	local s_port = ssh_port( parts[7] );
	local r_addr = ssh_addr( parts[8] );
	local r_port = ssh_port( parts[9] );
	local cid = ssh_count( parts[10] );

	#event ssh_connection_start(ts,sid,s_addr,s_port,r_addr,r_port,cid);

	return 0;
	}

function _ssh_connection_start_2(_data: string) : count
	{
	# event ssh_connection_start_2(ts:time, version: string, serv_interfaces: string, sid:string, s_addr:addr, s_port:port, r_addr:addr, r_port:port, cid:count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local serv_interfaces = ssh_string( parts[4] );
	local sid = ssh_string( parts[5] );
	local s_addr = ssh_addr( parts[6] );
	local s_port = ssh_port( parts[7] );
	local r_addr = ssh_addr( parts[8] );
	local r_port = ssh_port( parts[9] );
	local cid = ssh_count( parts[10] );

	event ssh_connection_start_2(ts,version,serv_interfaces,sid,s_addr,s_port,r_addr,r_port,cid);

	return 0;
	}

function _sshd_connection_end_3(_data: string) : count
	{
	# event sshd_connection_end_3(ts: time, version: string, sid: string, cid: count, r_addr: addr, r_port: port, l_addr: addr, l_port: port)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local r_addr = ssh_addr( parts[6] );
	local r_port = ssh_port( parts[7] );
	local l_addr = ssh_addr( parts[8] );
	local l_port = ssh_port( parts[9] );

	event sshd_connection_end_3(ts,version,sid,cid,r_addr,r_port,l_addr,l_port);

	return 0;
	}

function _sshd_connection_start_3(_data: string) : count
	{
	# event sshd_connection_start_3(ts: time, version: string, sid: string, cid: count, int_list: string, r_addr: addr, r_port: port, l_addr: addr, l_port: port, i: count)
	# sshd_connection_start_3 time=1342000800.858400 uristring=NMOD_3.08 uristring=931154466%3Agrace01%3A22 count=1398340635 uristring=127.0.0.1_10.77.1.10_128.55.81.74_128.55.34.74_10.10.10.208 addr=10.77.1.1 port=48744/tcp addr=0.0.0.0 port=22/tcp count=140737488349744
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local int_list = ssh_string( parts[6] );
	local r_addr = ssh_addr( parts[7] );
	local r_port = ssh_port( parts[8] );
	local l_addr = ssh_addr( parts[9] );
	local l_port = ssh_port( parts[10] );
	local i = ssh_count( parts[11] );

	event sshd_connection_start_3(ts,version,sid,cid,int_list,r_addr,r_port,l_addr,l_port,i);

	return 0;
	}

function _sshd_key_fingerprint(_data: string) : count
	{
	# event sshd_key_fingerprint(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, fingerprint:string, key_type:string)yy
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local serv_interfaces = ssh_string( parts[4] );
	local sid = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local fingerprint = ssh_string( parts[7] );
	local key_type = ssh_string( parts[8] );

	event sshd_key_fingerprint_2(ts,version,serv_interfaces,sid,cid,fingerprint,key_type);

	return 0;
	}

function _sshd_key_fingerprint_2(_data: string) : count
	{
	# event sshd_key_fingerprint_2(ts:time, version: string, serv_interfaces: string, sid:string, cid:count, fingerprint:string, key_type:string)yy
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local fingerprint = ssh_string( parts[7] );
	local key_type = ssh_string( parts[8] );

	event sshd_key_fingerprint_2(ts,sid,version,sid,cid,fingerprint,key_type);
	return 0;
	}

function _sshd_server_heartbeat_3(_data: string) : count
	{
	# event sshd_server_heartbeat_3(ts: time, version: string, sid: string,  dt: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local dt = ssh_count( parts[5] );

	event sshd_server_heartbeat_3(ts,version,sid,dt);

	return 0;
	}

function _sshd_start_3(_data: string) : count
	{
	# event sshd_start_3(ts: time, version: string, sid: string, h: addr, p: port)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local h = ssh_addr( parts[5] );
	local p = ssh_port( parts[6] );

	event sshd_start_3(ts,version,sid,h,p);

	return 0;
	}

function _ssh_login_fail(_data: string) : count
	{
	# no identified event
	return 0;
	}

function _ssh_login_fail_2(_data: string) : count
	{
	return 0;
	}

function _ssh_remote_do_exec(_data: string) : count
	{
	# event ssh_remote_do_exec(ts:time, sid:string, cid:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event ssh_remote_do_exec_2(ts,sid,version,serv_interfaces,cid,d);

	return 0;
	}

function _ssh_remote_do_exec_2(_data: string) : count
	{
	# event ssh_remote_do_exec_2(ts:time, sid:string, version:string, serv_interfaces: string, cid:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event ssh_remote_do_exec_2(ts,sid,version,serv_interfaces,cid,d);

	return 0;
	}

function _ssh_remote_exec_no_pty(_data: string) : count
	{
	# event ssh_remote_exec_no_pty_2(ts:time, sid:string, version:string, serv_interfaces:string, cid:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event ssh_remote_exec_no_pty_2(ts,sid,version,serv_interfaces,cid,d);

	return 0;
	}

function _ssh_remote_exec_no_pty_2(_data: string) : count
	{
	# event ssh_remote_exec_no_pty_2(ts:time, sid:string, version:string, serv_interfaces:string, cid:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event ssh_remote_exec_no_pty_2(ts,sid,version,serv_interfaces,cid,d);

	return 0;
	}

function _ssh_remote_exec_pty(_data: string) : count
	{
	# event ssh_remote_exec_pty(ts:time, sid:string, cid:count, _data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local cid = ssh_count( parts[4] );
	local d = ssh_string( parts[5] );

	event ssh_remote_exec_pty_2(ts,sid,cid,d);

	return 0;
	}

function _session_remote_exec_pty_3(_data: string) : count
	{
	# event session_remote_exec_pty_3(ts: time, version: string, sid: string, cid: count, channel: count, ppid: count, command: string) 
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local ppid = ssh_count( parts[7] );
	local command = ssh_string( parts[8] );

	event session_remote_exec_pty_3(ts,version,sid,cid,channel,ppid,command);

	return 0;
	}

function _channel_pass_skip_3(_data: string) : count
	{
	# event channel_pass_skip_3(ts: time, version: string, sid: string, cid: count, channel: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );

	event channel_pass_skip_3(ts,version,sid,cid,channel);

	return 0;
	}

function _auth_pass_attempt_3(_data: string) : count
	{
	# event auth_pass_attempt_3(ts: time, version: string, sid: string, cid: count, uid: string, password: string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local uid = ssh_string( parts[6] );
	local password = md5_hash( ssh_string( parts[7] ) );

	event auth_pass_attempt_3(ts,version,sid,cid,uid,password);

	return 0;
	}

function _sftp_process_symlink(_data: string) : count
	{
	# event event sftp_process_symlink(ts:time, sid:string, cid:count, old_path:string, new_path:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local cid = ssh_count( parts[4] );
	local old_path = ssh_string( parts[5] );
	local new_path = ssh_string( parts[6] );

	event sftp_process_symlink(ts,sid,cid,old_path,new_path);

	return 0;
	}

function _sftp_process_symlink_3(_data: string) : count
	{
	# event sftp_process_symlink_3(ts:time, version: string, sid:string, cid:count, ppid: int, old_path:string, new_path:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local old_path = ssh_string( parts[7] );
	local new_path = ssh_string( parts[8] );

	event sftp_process_symlink_3(ts,version,sid,cid,ppid,old_path,new_path);

	return 0;
	}

function _sftp_process_mkdir(_data: string) : count
	{
	# event sftp_process_mkdir(ts:time, sid:string, cid:count, data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local cid = ssh_count( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_mkdir(ts,sid,cid,d);

	return 0;
	}

function _sftp_process_mkdir_3(_data: string) : count
	{
	# event sftp_process_mkdir_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_mkdir_3(ts,version,sid,cid,ppid,d);

	return 0;
	}
function _invalid_user(_data: string) : count
	{
	#event invalid_user(ts:time, sid:string, version: string, interface:string, uid:string, cid: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local interface = ssh_string( parts[5] );
	local uid = ssh_string( parts[6] );
	local cid = ssh_count( parts[7] );

	event invalid_user_2(ts,sid,version,interface,uid,cid);

	return 0;
	}	

function _invalid_user_2(_data: string) : count
	{
	#event invalid_user_2(ts:time, sid:string, version: string, serv_interfaces: string, uid:string, cid: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local sid = ssh_string( parts[3] );
	local version = ssh_string( parts[4] );
	local serv_interfaces = ssh_string( parts[5] );
	local uid = ssh_string( parts[6] );
	local cid = ssh_count( parts[7] );

	event invalid_user_2(ts,sid,version,serv_interfaces,uid,cid);

	return 0;
	}	

function _auth_invalid_user_3(_data: string) : count
	{
	#event auth_invalid_user_3(ts: time, version: string, sid: string, cid: count, uid: string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local uid = ssh_string( parts[6] );

	event auth_invalid_user_3(ts,version,sid,cid,uid);

	return 0;
	}	

function _channel_port_open_3(_data: string) : count
	{
	#event channel_port_open_3(ts: time, version: string, sid: string, cid: count, channel: count, rtype: string, l_port: port, path: string, h_port: port, rem_host: string, rem_port: port)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local rtype = ssh_string( parts[7] );
	local l_port = ssh_port( parts[8] );
	local path = ssh_string( parts[9] );
	local h_port = ssh_port( parts[10] );
	local rem_host = ssh_string( parts[11] );
	local rem_port = ssh_port( parts[12] );

	event channel_port_open_3(ts,version,sid,cid,channel,rtype,l_port,path,h_port,rem_host,rem_port);

	return 0;
	}

function _channel_portfwd_req_3(_data: string) : count
	{
	#event channel_portfwd_req_3(ts: time, version: string, sid: string, cid: count, channel:count, host: string, fwd_port: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local host = ssh_string( parts[7] );
	local fwd_port = ssh_count( parts[8] );

	event channel_portfwd_req_3(ts,version,sid,cid,channel,host,fwd_port);

	return 0;
	}	

function _channel_post_fwd_listener_3(_data: string) : count
	{
	#event channel_post_fwd_listener_3(ts: time, version: string, sid: string, cid: count, channel: count, l_port: port, path: string, h_port: port, rtype: string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local l_port = ssh_port( parts[7] );
	local path = ssh_string( parts[8] );
	local h_port = ssh_port( parts[9] );
	local rtype = ssh_string( parts[10] );

	event channel_post_fwd_listener_3(ts,version,sid,cid,channel,l_port,path,h_port,rtype);

	return 0;
	}

function _channel_set_fwd_listener_3(_data: string) : count
	{
	#event channel_set_fwd_listener_3(ts: time, version: string, sid: string, cid: count, channel: count, c_type: count, wildcard: count, forward_host: string, l_port: port, h_port: port)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local c_type = ssh_count( parts[7] );
	local wildcard = ssh_count( parts[8] );
	local forward_host = ssh_string( parts[9] );
	local l_port = ssh_port( parts[10] );
	local h_port = ssh_port( parts[11] );

	event channel_set_fwd_listener_3(ts,version,sid,cid,channel,c_type,wildcard,forward_host,l_port,h_port);

	return 0;
	}

function _channel_socks4_3(_data: string) : count
	{
	#event channel_socks4_3(ts: time, version: string, sid: string, cid: count, channel: count, path: string, h_port: port, command: count, username: string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local path = ssh_string( parts[7] );
	local h_port = ssh_port( parts[8] );
	local command = ssh_count( parts[9] );
	local username = ssh_string( parts[10] );

	event channel_socks4_3(ts,version,sid,cid,channel,path,h_port,command,username);

	return 0;
	}

function _channel_socks5_3(_data: string) : count
	{
	#event channel_socks5_3(ts: time, version: string, sid: string, cid: count, channel: count, path: string, h_port: port, command: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local path = ssh_string( parts[7] );
	local h_port = ssh_port( parts[8] );
	local command = ssh_count( parts[9] );

	event channel_socks5_3(ts,version,sid,cid,channel,path,h_port,command);

	return 0;
	}

function _session_do_auth_3(_data: string) : count
	{
	#event session_do_auth_3(ts: time, version: string, sid: string, cid: count, atype: count, type_ret: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local atype = ssh_count( parts[6] );
	local type_ret = ssh_count( parts[7] );

	event session_do_auth_3(ts,version,sid,cid,atype,type_ret);

	return 0;
	}

function _session_tun_init_3(_data: string) : count
	{
	#event session_tun_init_3(ts: time, version: string, sid: string, cid: count, channel: count, mode: count)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local channel = ssh_count( parts[6] );
	local mode = ssh_count( parts[7] );

	event session_tun_init_3(ts,version,sid,cid,channel,mode);

	return 0;
	}

function _sftp_process_remove_3(_data: string) : count
	{
	#event sftp_process_remove_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_remove_3(ts,version,sid,cid,ppid,d);

	return 0;
	}

function _sftp_process_rmdir_3(_data: string) : count
	{
	#event sftp_process_rmdir_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_rmdir_3(ts,version,sid,cid,ppid,d);

	return 0;
	}

function _sftp_process_unknown_3(_data: string) : count
	{
	#event sftp_process_unknown_3(ts:time, version: string, sid:string, cid:count, ppid: int, data:string)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local cid = ssh_count( parts[5] );
	local ppid = ssh_int( parts[6] );
	local d = ssh_string( parts[7] );

	event sftp_process_unknown_3(ts,version,sid,cid,ppid,d);

	return 0;
	}

function _sshd_exit_3(_data: string) : count
	{
	#event sshd_exit_3(ts: time, version: string, sid: string, h: addr, p: port)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local h = ssh_addr( parts[5] );
	local p = ssh_port( parts[6] );

	event sshd_exit_3(ts,version,sid,h,p);

	return 0;
	}

function _sshd_restart_3(_data: string) : count
	{
	#event sshd_restart_3(ts: time, version: string, sid: string, h: addr, p: port)
	local parts = split(_data, kv_splitter);

	local ts = ssh_time( parts[2] );
	local version = ssh_string( parts[3] );
	local sid = ssh_string( parts[4] );
	local h = ssh_addr( parts[5] );
	local p = ssh_port( parts[6] );

	event sshd_restart_3(ts,version,sid,h,p);

	return 0;
	}

function _pass_xxx(_data: string) : count
	{
	return 0;
	}

# ### ---------- ###
#
# this generates the mapping between the name of the event, and the function that we will use to 
#  call and generate 
#
# ### ---------- ###

redef dispatcher += {
	["PASS_XXX"] = _pass_xxx,
	["auth_info_3"] = _auth_info_3,
	["auth_key_fingerprint_3"] = _auth_key_fingerprint_3,
	["auth_ok"] = _auth_ok,
	["auth_ok_2"] = _auth_ok_2,
	["auth_pass_attempt_3"] = _auth_pass_attempt_3,
	["channel_data_client_3"] = _channel_data_client_3,
	["channel_data_server_3"] = _channel_data_server_3,
	["channel_data_server_sum_3"] = _channel_data_server_sum_3,
	["channel_exit"] = _channel_exit,
	["channel_exit_2"] = _channel_exit_2,
	["channel_free_3"] = _channel_free_3,
	["channel_new_3"] = _channel_new_3,
	["channel_notty_analysis_disable_3"] = _channel_notty_analysis_disable_3,
	["channel_notty_client_data_3"] = _channel_notty_client_data_3,
	["channel_notty_server_data_3"] = _channel_notty_server_data_3,
	["channel_pass_skip_3"] = _channel_pass_skip_3,
	["data_client"] = _data_client,
	["data_client_2"] = _data_client_2,
	["data_server"] = _data_server,
	["data_server_2"] = _data_server_2,
	["data_server_sum"] = _data_server_sum,
	["data_server_sum_2"] = _data_server_sum_2,
	["new_channel_session"] = _new_channel_session,
	["new_channel_session_2"] = _new_channel_session_2,
	["new_session"] = _new_session,
	["new_session_2"] = _new_session_2,
	["notty_analysis_disable"] = _notty_analysis_disable,
	["notty_analysis_disable_2"] = _notty_analysis_disable_2,
	["notty_client_data"] = _notty_client_data,
	["notty_client_data_2"] = _notty_client_data_2,
	["notty_server_data"] = _notty_server_data,
	["notty_server_data_2"] = _notty_server_data_2,
	["server_heartbeat"] = _server_heartbeat,
	["server_heartbeat_2"] = _server_heartbeat_2,
	["server_input_channel_open"] = _server_input_channel_open,
	["server_input_channel_open_2"] = _server_input_channel_open_2,
	["session_channel_request_3"] = _session_channel_request_3,
	["session_exit_3"] = _session_exit_3,
	["session_input_channel_open_3"] = _session_input_channel_open_3,
	["session_new_3"] = _session_new_3,
	["session_remote_do_exec_3"] = _session_remote_do_exec_3,
	["session_remote_exec_no_pty_3"] = _session_remote_exec_no_pty_3,
	["session_request_direct_tcpip_3"] = _session_request_direct_tcpip_3,
	["server_request_direct_tcpip"] = _server_request_direct_tcpip,
	["server_request_direct_tcpip_2"] = _server_request_direct_tcpip_2,
	["session_x11fwd_3"] = _session_x11fwd_3,
	["sftp_process_close"] = _sftp_process_close,
	["sftp_process_close_2"] = _sftp_process_close_2,
	["sftp_process_close_3"] = _sftp_process_close_3,
	["sftp_process_do_stat"] = _sftp_process_do_stat,
	["sftp_process_do_stat_2"] = _sftp_process_do_stat_2,
	["sftp_process_do_stat_3"] = _sftp_process_do_stat_3,
	["sftp_process_fsetstat"] = _sftp_process_fsetstat,
	["sftp_process_fsetstat_3"] = _sftp_process_fsetstat_3,
	["sftp_process_init"] = _sftp_process_init,
	["sftp_process_init_2"] = _sftp_process_init,
	["sftp_process_init_3"] = _sftp_process_init_3,
	["sftp_process_mkdir"] = _sftp_process_mkdir,
	["sftp_process_mkdir_3"] = _sftp_process_mkdir_3,
	["sftp_process_open"] = _sftp_process_open,
	["sftp_process_open_2"] = _sftp_process_open,
	["sftp_process_open_3"] = _sftp_process_open_3,
	["sftp_process_opendir"] = _sftp_process_opendir,
	["sftp_process_opendir_2"] = _sftp_process_opendir_2,
	["sftp_process_opendir_3"] = _sftp_process_opendir_3,
	["sftp_process_readdir"] = _sftp_process_readdir,
	["sftp_process_readdir_2"] = _sftp_process_readdir_2,
	["sftp_process_readdir_3"] = _sftp_process_readdir_3,
	["sftp_process_rename"] = _sftp_process_rename,
	["sftp_process_rename_2"] = _sftp_process_rename_2,
	["sftp_process_rename_3"] = _sftp_process_rename_3,
	["sftp_process_realpath"] = _sftp_process_realpath,
	["sftp_process_realpath_3"] = _sftp_process_realpath_3,
	["sftp_process_remove"] = _sftp_process_remove,
	["sftp_process_readlink"] = _sftp_process_readlink,
	["sftp_process_readlink_2"] = _sftp_process_readlink_2,
	["sftp_process_readlink_3"] = _sftp_process_readlink_3,
	["sftp_process_setstat"] = _sftp_process_setstat_2,
	["sftp_process_setstat_2"] = _sftp_process_setstat_2,
	["sftp_process_setstat_3"] = _sftp_process_setstat_3,
	["sftp_process_fstat"] = _sftp_process_fstat,
	["sftp_process_fstat_2"] = _sftp_process_fstat,
	["sftp_process_fstat_3"] = _sftp_process_fstat_3,
	["sftp_process_symlink"] = _sftp_process_symlink,
	["sftp_process_symlink_3"] = _sftp_process_symlink_3,
	["ssh_connection_end"] = _ssh_connection_end,
	["ssh_connection_end_2"] = _ssh_connection_end_2,
	["ssh_connection_start"] = _ssh_connection_start,
	["ssh_connection_start_2"] = _ssh_connection_start_2,
	["sshd_connection_end_3"] = _sshd_connection_end_3,
	["sshd_connection_start_3"] = _sshd_connection_start_3,
	["sshd_key_fingerprint"] = _sshd_key_fingerprint,
	["sshd_key_fingerprint_2"] = _sshd_key_fingerprint_2,
	["sshd_server_heartbeat_3"] = _sshd_server_heartbeat_3,
	["sshd_start_3"] = _sshd_start_3,
	["ssh_login_fail"] = _ssh_login_fail,
	["ssh_login_fail_2"] = _ssh_login_fail_2,
	["ssh_remote_do_exec"] = _ssh_remote_do_exec,
	["ssh_remote_do_exec_2"] = _ssh_remote_do_exec_2,
	["ssh_remote_exec_no_pty"] = _ssh_remote_exec_no_pty,
	["ssh_remote_exec_no_pty_2"] = _ssh_remote_exec_no_pty_2,
	["ssh_remote_exec_pty"] = _ssh_remote_exec_pty,
	["invalid_user_2"] = _invalid_user_2,
	["auth_invalid_user_3"] = _auth_invalid_user_3,
	["channel_port_open_3"] = _channel_port_open_3,
	["channel_portfwd_req_3"] = _channel_portfwd_req_3,
	["channel_post_fwd_listener_3"] = _channel_post_fwd_listener_3,
	["channel_set_fwd_listener_3"] = _channel_set_fwd_listener_3,
	["channel_socks4_3"] = _channel_socks4_3,
	["channel_socks5_3"] = _channel_socks5_3,
	["session_do_auth_3"] = _session_do_auth_3,
	["session_remote_exec_pty_3"] = _session_remote_exec_pty_3,
	["session_tun_init_3"] = _session_tun_init_3,
	["sftp_process_remove_3"] = _sftp_process_remove_3,
	["sftp_process_rmdir_3"] = _sftp_process_rmdir_3,
	["sftp_process_unknown_3"] = _sftp_process_unknown_3,
	["sshd_exit_3"] = _sshd_exit_3,
	["sshd_restart_3"] = _sshd_restart_3,
	};

redef argument_count += {
	["auth_info_3"] = vector( 12 ),
	["auth_invalid_user_3"] = vector( 6 ),
	["auth_key_fingerprint_3"] = vector( 7 ),
	["auth_ok_2"] = vector( 12 ),
	["auth_ok"] = vector( 12 ),
	["auth_pass_attempt_3"] = vector( 7 ),
	["channel_data_client_3"] = vector( 7 ),
	["channel_data_server_3"] = vector( 7 ),
	["channel_data_server_sum_3"] = vector( 7 ),
	["channel_free_3"] = vector( 7 ),
	["channel_new_3"] = vector( 8 ),
	["channel_notty_analysis_disable_3"] = vector( 7,8 ),
	["channel_notty_client_data_3"] = vector( 7 ),
	["channel_notty_server_data_3"] = vector( 7 ),
	["channel_pass_skip_3"] = vector( 6 ),
	["channel_portfwd_req_3"] = vector( 8 ),
	["channel_port_open_3"] = vector( 12 ),
	["channel_post_fwd_listener_3"] = vector( 10 ),
	["channel_set_fwd_listener_3"] = vector( 11 ),
	["channel_socks4_3"] = vector( 10 ),
	["channel_socks5_3"] = vector( 9 ),
	["data_client_2"] = vector( 8 ),
	["data_server_2"] = vector( 9 ),
	["data_client"] = vector( 8 ),
	["data_server"] = vector( 9 ),
	["data_server_sum_2"] = vector( 8 ),
	["data_server_sum"] = vector( 8 ),
	["invalid_user_2"] = vector( 7 ),
	["new_channel_session"] = vector( 8 ),
	["new_channel_session_2"] = vector( 8 ),
	["new_session_2"] = vector( 7 ),
	["notty_analysis_disable_2"] = vector( 8 ),
	["notty_client_data"] = vector( 8 ),
	["notty_client_data_2"] = vector( 8 ),
	["notty_server_data"] = vector( 8 ),
	["notty_server_data_2"] = vector( 8 ),
	["server_request_direct_tcpip_2"] = vector( 10 ),
	["server_heartbeat"] = vector( 6 ),
	["server_heartbeat_2"] = vector( 6 ),
	["session_channel_request_3"] = vector( 8 ),
	["session_do_auth_3"] = vector( 7 ),
	["session_exit_3"] = vector( 8 ),
	["session_input_channel_open_3"] = vector( 10 ),
	["session_new_3"] = vector( 7 ),
	["session_remote_do_exec_3"] = vector( 8 ),
	["session_remote_exec_no_pty_3"] = vector( 8 ),
	["session_remote_exec_pty_3"] = vector( 8 ),
	["session_request_direct_tcpip_3"] = vector( 11 ),
	["session_tun_init_3"] = vector( 7 ),
	["session_x11fwd_3"] = vector( 7 ),
	["sftp_process_close_3"] = vector( 8 ),
	["sftp_process_close"] = vector( 8 ),
	["sftp_process_do_stat_3"] = vector( 7 ),
	["sftp_process_do_stat"] = vector( 7 ),
	["sftp_process_fsetstat_3"] = vector( 8 ),
	["sftp_process_fsetstat"] = vector( 8 ),
	["sftp_process_fstat"] = vector( 8 ),
	["sftp_process_init_3"] = vector( 8 ),
	["sftp_process_init"] = vector( 8 ),
	["sftp_process_mkdir_3"] = vector( 7 ),
	["sftp_process_mkdir"] = vector( 7 ),
	["sftp_process_open_3"] = vector( 7 ),
	["sftp_process_open"] = vector( 7 ),
	["sftp_process_opendir_3"] = vector( 7 ),
	["sftp_process_opendir"] = vector( 7 ),
	["sftp_process_readdir_3"] = vector( 7 ),
	["sftp_process_readdir"] = vector( 7 ),
	["sftp_process_readlink_3"] = vector( 7 ),
	["sftp_process_readlink"] = vector( 7 ),
	["sftp_process_realpath_3"] = vector( 7 ),
	["sftp_process_realpath"] = vector( 7 ),
	["sftp_process_remove_3"] = vector( 7 ),
	["sftp_process_remove"] = vector( 7 ),
	["sftp_process_rename_3"] = vector( 8 ),
	["sftp_process_rename"] = vector( 6 ),
	["sftp_process_rmdir_3"] = vector( 7 ),
	["sftp_process_setstat_3"] = vector( 8 ),
	["sftp_process_setstat"] = vector( 8 ),
	["sftp_process_symlink_3"] = vector( 8 ),
	["sftp_process_symlink"] = vector( 6 ),
	["sftp_process_unknown_3"] = vector( 7 ),
	["ssh_connection_end_2"] = vector( 10 ),
	["ssh_connection_start"] = vector( 10 ),
	["ssh_connection_start_2"] = vector( 10 ),
	["sshd_connection_end_3"] = vector( 9 ),
	["sshd_connection_start_3"] = vector( 11 ),
	["sshd_exit_3"] = vector( 6 ),
	["ssh_login_fail"] = vector( 7 ),
	["ssh_login_fail_2"] = vector( 7 ),
	["sshd_key_fingerprint"] = vector( 8 ),
	["sshd_key_fingerprint_2"] = vector( 8 ),
	["sshd_restart_3"] = vector( 6 ),
	["sshd_server_heartbeat_3"] = vector( 5 ),
	["sshd_start_3"] = vector( 6 ),
	["ssh_remote_do_exec_2"] = vector( 7 ),
	["ssh_remote_exec_no_pty_2"] = vector( 7 ),
	["ssh_remote_exec_pty_2"] = vector( 5 ),
	["channel_exit_2"] = vector( 8 ),
	["channel_exit"] = vector( 8 ),
	["new_session"] = vector( 7 ),
	["notty_analysis_disable"] = vector( 8 ),
	["PASS_XXX"] = vector( 6 ),
	["server_input_channel_open"] = vector( 9 ),
	["server_input_channel_open_2"] = vector( 9 ),
	["server_request_direct_tcpip"] = vector( 10 ),
	["sftp_process_close_2"] = vector( 8 ),
	["sftp_process_do_stat_2"] = vector( 7 ),
	["sftp_process_fstat_2"] = vector( 7 ),
	["sftp_process_fstat_3"] = vector( 7 ),
	["sftp_process_init_2"] = vector( 8 ),
	["sftp_process_open_2"] = vector( 7 ),
	["sftp_process_opendir_2"] = vector( 7 ),
	["sftp_process_readdir_2"] = vector( 7 ),
	["sftp_process_readlink_2"] = vector( 7 ),
	["ssh_connection_end"] = vector( 10 ),
	["ssh_remote_do_exec"] = vector( 7 ),
	["ssh_remote_exec_no_pty"] = vector( 7 ),
	["ssh_remote_exec_pty"] = vector( 7 ),
	};

event sshLine(description: Input::EventDescription, tpe: Input::Event, LV: lineVals)
	{

	local t_d = gsub(LV$d, /\x20\x20/, " ");	
	LV$d = t_d;
        local parts = split(LV$d, kv_splitter);
	local l_parts = |parts|;
	local ni: count = 2;

	# count the transaction record
	++input_count;

	# get the event name
	local event_name = parts[1];
	
	# there is no reason for this value to be this low for a legitimate line
	if ( l_parts < 5 )
		return;
	
	if ( event_name in dispatcher ) {
		if ( event_name in argument_count ) {
			local arg_set = argument_count[event_name];
			local i: count;
			for ( i in arg_set ) {
				if ( l_parts == arg_set[i] ) {
					dispatcher[event_name](LV$d);
					return;
					}
				}


			# this is a bit arbitrary for now
			if ( l_parts > 10 ) {

				local m_event = split_all(t_d, multi_match);
				local j:count;
				local n:count;

				# we know that there will be at least one of these ..
				# the general form is [1]: skip, [2][3] , [4][5] , ...
				for ( j in v2s ) {
					n = v2s[j];

					if ( n+1 <= |m_event| ) {
						local t_data: string = fmt("%s%s", m_event[n], m_event[n+1]);
						local t_event: string = strip(fmt("%s",m_event[n]));
						LV$d = t_data;
						#print fmt("FIX: |%s|",t_event );
						dispatcher[t_event](LV$d);
						}
					}
				} # end main multipart outer loop
			} # end of event_name in dispatcher
		else {
			#print fmt("NOT IN ARG-COUNT: %s", event_name);
			}
		}
	else {

		# since a significant number of "unknown" errors are just
		#  off by one give parts[2] a try
		if ( parts[2] in dispatcher ) {

			local parts_mod = split1(LV$d, kv_splitter);
			# call the function with the identified name: parts[2]
			# using the snipped off data: parts_mod[2] which contains the original 
			#  data string with the initial member snipped off
			dispatcher[ parts[2] ](parts_mod[2]);
			}
		else {
			if ( notify_unknown_event ) {
				NOTICE([$note=SSHD_INPUT_UnknownEvent,
					$msg=fmt("Unknown event %s", event_name)]);
				}
			}	
		}
	}

event stop_reader()
	{
	if ( stop_sem == 0 ) {
		Input::remove("isshd");
		stop_sem = 1;
		}
	}

event start_reader()
	{
	if ( stop_sem == 1 ) { 
		Input::add_event([$source=data_file, $reader=Input::READER_RAW, $mode=Input::TSTREAM, $name="isshd", $fields=lineVals, $ev=sshLine]);
		stop_sem = 0;
		}
	}

event transaction_rate()
	{
	#if ( ! input_count_test )
	#	return;

	local delta = input_count - input_count_prev;
	print fmt("Log delta: %s", delta);

	# rate is too low - send a notice the first time
	if ( (delta > 0) && (delta < input_low_water) ) {

		# only send the notice on the first instance 
		if ( input_count_state != 2 )
			NOTICE([$note=SSHD_INPUT_LowTransactionRate,
				$msg=fmt("event rate %s per %s", delta, input_test_interval)]);
		
		input_count_state = 2; # 2: low transaction rate	
		}

	# perhaps the data file has rotated out from under the input descriptor?
	if (delta < input_low_water) {
		schedule 1 sec { stop_reader() };
		schedule 10 sec { start_reader() };
		}

	# rate is ok
	if ( (delta > 0) && (delta > input_low_water) ) {
		input_count_state = 1;
		}

	# rotate values
	input_count_prev = input_count;

	# reschedule this all over again ...
	schedule input_test_interval { transaction_rate() };
	}

event bro_init()
	{
	# input stream setup
	if ( (Cluster::local_node_type() == Cluster::WORKER) && (file_size(data_file) != -1.0) ) {
		print fmt("%s SSHD data file %s located", gethostname(), data_file);
		Input::add_event([$source=data_file, $reader=Input::READER_RAW, $mode=Input::TSTREAM, $name="isshd", $fields=lineVals, $ev=sshLine]);

		# start rate monitoring for event stream 
		schedule input_test_interval { transaction_rate() };
		}
	else
		print fmt("%s SSHD data file %s not found", gethostname(), data_file);
	}
