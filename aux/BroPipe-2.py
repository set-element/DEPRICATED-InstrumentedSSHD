#!/Library/Frameworks/Python.framework/Versions/2.7/bin/python
#
# channel_notty_analysis_disable_3 time=1329926319.305358 uristring=NMOD_3.08 uristring=3331882995%3Asg1.nersc.gov%3A22 count=1593597883 count=2 int=633 int=392

#

from tail import FileTail
#from broccoli import *
import broccoli
import urllib
import syslog
import time
import socket

#channel_notty_analysis_disable_3 = record_type("ts", "version", "sid", "cid"
# track both events/sec as well as diff between gettimeofday() and the recorded dt
# track error counters
# create infrastructure events for this?

total_event_count = 0

window_event_count = 0                         # events per window
window_start_time = broccoli.current_time()    # 
window_size = 60                               # measuring window in seconds

alarm_event_rate = 10000
node = "127.0.0.1:47757"
event = "BLANK"
valset = []

error_line = 0   # the event line does not contain at least two entries
error_item = 0   # number of '=' in the type=data < 1
error_parse = 0  # data parse errors per window

# init the connection object, but do not attempt to connect
bro_conn = broccoli.Connection(connect=False,destination=node)

syslog.openlog()

# file to monitor
#t = FileTail("logfile")
t = FileTail("/var/www/html/sigma/ssh_logging")

# ----------### Functions Below ###---------- #
def databrush(type,dval):

    # patch for broken heartbeat
    if event.find('server_heartbeat') != -1  and dval == "-1":
         return "0"
    # IPv6 address raw socket looks like "::", make a fave IPv4 address of the same
    #  form in order to maintain bookeeping
    # A "normal" IPv6 address will not be changed by this 
    if type == "addr" and dval == "::":
         return "0.0.0.0"



    return dval

def broconnect():
    global bro_conn
    result = False

    while result == False:
        try:
            print "connection attempt to ", node
            bro_conn = broccoli.Connection(node)
        except:
            print "connection fail to node ", node
            time.sleep(1)
        else:
            result = True

# function for checking rate of events
# return 0 if window has elapsed
def event_rate(wst):
    global error_line
    global error_item
    global error_parse
    now = broccoli.current_time()
    ret = 1

    if now - wst >= window_size :
        if now - wst > 0 :
            rate = ( window_event_count / (now - wst) )
            syslog.syslog("bropipe rate: %s event/sec" % rate)
            print "Rate: ", rate

            if rate > alarm_event_rate:
                syslog.syslog("bropipe excess rate: %s event/sec" % rate)

            if error_line + error_item + error_parse > 0:
                syslog.syslog("bropipe error line: %s item: %s parse: %s" % (error_line,error_item,error_parse) )
                print "bropipe error line: %s item: %s parse: %s" % (error_line,error_item,error_parse)
                error_line = 0
                error_item = 0
                error_parse = 0                
        ret = 0
    return ret

def is_valid_ipv4_address(address):
    try:
        addr=socket.inet_pton(socket.AF_INET, address)
    except AttributeError: # no inet_pton here, sorry
        try:
            addr=socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error: # not a valid address
        return False
    
    return True

def is_valid_ipv6_address(address):
    try:
        addr= socket.inet_pton(socket.AF_INET6, address)
    except socket.error: # not a valid address
        return False
    return True

def is_valid_ip(address):
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)

def is_valid_port(port):
    try:
        p = port.split('/')
    except (IndexError, ValueError):
        return False
    if ( p[1] != "tcp" and p[1] != "udp" and p[1] != "icmp" ):
        print p[1]
        return False

    return len(p) == 2 and p[0].isdigit()

# ----------### Main work Loop ###---------- #
syslog.syslog("starting bropipe")
broconnect()
syslog.syslog("bropipe started")
for line in t:

    line = line.rstrip(' \n\r')
    l = line.split()
    # print total_event_count
    # we expect a minimum form of: <event> <data>
    # if this is not the case, something is probably wrong and we bail
    if len(l) < 2:
        #print "skipping line: ", line, " len:", len(l)
        error_line = error_line + 1
        print "     line ", line
        continue

    # reset count for current event
    item_count = 0
    # increment running event count
    total_event_count = total_event_count + 1
    window_event_count = window_event_count + 1

    # check rate
    if total_event_count % 10 == 0:
       if event_rate(window_start_time) == 0:
            window_event_count = 0
            window_start_time = broccoli.current_time()
    valset = []

    for item in l:
        
        item_count = item_count + 1
        item.rstrip(' ')

        # count 1 is just the name of the event
        # all other items should be key=value pairs
        if item_count == 1:
            event = item
            #event = bro_event_new(item)
            #print total_event_count, ":", window_event_count," event: ", item
        else:

            # this makes sure that there is data after the '='
            # for no data we skip the item and try to move on
            if item.count('=')< 1 :
                #print "skipping item ", item
                error_item = error_item + 1
                print "          item:", item
                continue

            element = item.split("=") 
            type = element[0]

            if type == "bool":
                if element[1] == "T" or element[1] == "F":
                    val = element[1]
                else:
                    print "               parse bool:",element[1]
                    error_parse = error_parse + 1
                    continue
            elif type == "count":
                element[1] = databrush(type,element[1])

                if element[1].isdigit():
                    val = broccoli.count(element[1])
                else:
                    error_parse = error_parse + 1
                    print "               parse count:",element[1], " ", event
                    continue
            elif type == "time":
                try:
                    tval = float(element[1])
                except ValueError, TypeError:
                    error_parse = error_parse + 1
                    print "               parse time:",element[1]
                    continue
                else:
                    val = broccoli.time(element[1])
            elif type == "interval":
                val = broccoli.interval(element[1])
            elif type == "double":
                try: 
                    val = float(element[1])
                except ValueError, TypeError:
                    print "               parse double:",element[1]
                    error_parse = error_parse + 1
                    continue
            elif type == "string":
                val = element[1]
            elif type == "uristring":
                val = urllib.unquote_plus( str(element[1]) )
            elif type == "port":
                if element[1].find('/tcp') == -1:
                    element[1] = element[1] + '/tcp'
                if is_valid_port(element[1]):
                    val = broccoli.port(element[1])
                else:
                    error_parse = error_parse + 1
                    print "               parse port:",element[1]
                    continue
            elif type == "addr":
                element[1] = databrush(type,element[1])

                if is_valid_ipv4_address(element[1]):
                    val = broccoli.addr(element[1])
                else:
                    error_parse = error_parse + 1
                    print "               parse addr:",element[1]
                    continue
            elif type == "subnet":
                val = broccoli.subnet(element[1])
            elif type == "int":
                try:
                    val = int(element[1])
                except ValueError:
                    error_parse = error_parse + 1
                    print "               parse int:",element[1]
                    continue
            else:
                #print "unknown type: ", type
                 error_parse = error_parse + 1
                 print "               parse unknown:",element[1]
                 continue

            valset.append(val)
    # end for item in l, generate event and send
    #print "end of loop"
    item_count = 0
    bro_conn.send(event, *valset)


