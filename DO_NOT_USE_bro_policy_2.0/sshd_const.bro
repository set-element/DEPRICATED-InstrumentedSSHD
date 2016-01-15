# 03/25/2011: Scott Campbell
# 
# constants for session and logging info: note that this is *not* using
#   the scoping/module framework so lovingly developed by the Bro Overlords.
# 

const AUTH_FAIL = 0;	# fail
const AUTH_UNKNOWN = 1;	# default
const AUTH_OK = 2;	# success

# This set defines the types of line_parse() types
const LINE_SUSPICOUS = 0;
const LINE_CLIENT = 1;
const LINE_SERVER = 2;
const LINE_HOSTILE = 3;

# Definitions for channel types. #
const SSH_CHANNEL_X11_LISTENER        = 1;  #     /* Listening for inet X11 conn. */
const SSH_CHANNEL_PORT_LISTENER       = 2;  #     /* Listening on a port. */
const SSH_CHANNEL_OPENING             = 3;  #     /* waiting for confirmation */
const SSH_CHANNEL_OPEN                = 4;  #     /* normal open two-way channel */
const SSH_CHANNEL_CLOSED              = 5;  #     /* waiting for close confirmation */
const SSH_CHANNEL_AUTH_SOCKET         = 6;  #     /* authentication socket */
const SSH_CHANNEL_X11_OPEN            = 7;  #     /* reading first X11 packet */
const SSH_CHANNEL_INPUT_DRAINING      = 8;  #     /* sending remaining data to conn */
const SSH_CHANNEL_OUTPUT_DRAINING     = 9;  #     /* sending remaining data to app */
const SSH_CHANNEL_LARVAL              = 10; #     /* larval session */
const SSH_CHANNEL_RPORT_LISTENER      = 11; #     /* Listening to a R-style port  */
const SSH_CHANNEL_CONNECTING          = 12;
const SSH_CHANNEL_DYNAMIC             = 13;
const SSH_CHANNEL_ZOMBIE              = 14; #     /* Almost dead. */
const SSH_CHANNEL_MUX_LISTENER        = 15; #     /* Listener for mux conn. */
const SSH_CHANNEL_MUX_CLIENT          = 16; #     /* Conn. to mux slave */
const SSH_CHANNEL_MAX_TYPE            = 17;

# table to get name from type for channel info
global channel_name: table[count] of string = {
	[1] = "SSH_CHANNEL_X11_LISTENER",
	[2] = "SSH_CHANNEL_PORT_LISTENER",
	[3] = "SSH_CHANNEL_OPENING",
	[4] = "SSH_CHANNEL_OPEN",
	[5] = "SSH_CHANNEL_CLOSED",
	[6] = "SSH_CHANNEL_AUTH_SOCKET",
	[7] = "SSH_CHANNEL_X11_OPEN",
	[8] = "SSH_CHANNEL_INPUT_DRAINING",
	[9] = "SSH_CHANNEL_OUTPUT_DRAINING",
	[10] = "SSH_CHANNEL_LARVAL",
	[11] = "SSH_CHANNEL_RPORT_LISTENER",
	[12] = "SSH_CHANNEL_CONNECTING",
	[13] = "SSH_CHANNEL_DYNAMIC",
	[14] = "SSH_CHANNEL_ZOMBIE",
	[15] = "SSH_CHANNEL_MUX_LISTENER",
	[16] = "SSH_CHANNEL_MUX_CLIENT",
	[17] = "SSH_CHANNEL_MAX_TYPE",
};

# socks5 data header types: taken from channels.c, not sure what is up with the
#  duplicate data/index values...
const SSH_SOCKS5_AUTHDONE	= 4096;
const SSH_SOCKS5_NOAUTH		= 0;
const SSH_SOCKS5_IPV4		= 1;
const SSH_SOCKS5_DOMAIN		= 3;
const SSH_SOCKS5_IPV6		= 4;
const SSH_SOCKS5_CONNECT	= 1;
const SSH_SOCKS5_SUCCESS	= 0;

global socks5_header_types: table[count] of string = {
	[0] = "SSH_SOCKS5_SUCCESS",
	#[0] = "SSH_SOCKS5_NOAUTH",
	[1] = "SSH_SOCKS5_IPV4",
	#[1] = "SSH_SOCKS5_CONNECT",
	[3] = "SSH_SOCKS5_DOMAIN",
	[4] = "SSH_SOCKS5_IPV6",
};

# ssh tunnel info

const SSH_TUNMODE_NO          = 0;
const SSH_TUNMODE_POINTOPOINT = 1;
const SSH_TUNMODE_ETHERNET    = 2;
#const SSH_TUNMODE_DEFAULT     SSH_TUNMODE_POINTOPOINT
#const SSH_TUNMODE_YES         (SSH_TUNMODE_POINTOPOINT|SSH_TUNMODE_ETHERNET)

global tunnel_type: table[count] of string = {
	[0] = "SSH_TUNMODE_NO",
	[1] = "SSH_TUNMODE_POINTOPOINT",
	[2] = "SSH_TUNMODE_ETHERNET",
};

