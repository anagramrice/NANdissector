from scapy.all import *
import traceback as tb
import re

actsubtype = ['Reserved',
'Ranging Request',
'Ranging Response',
'Ranging Termination',
'Ranging Report',
'Data Path Request',
'Data Path Response',
'Data Path Confirm',
'Data Path Key Installment',
'Data Path Termination',
'Schedule Request',
'Schedule Response',
'Schedule Confirm',
'Schedule Update Notification']

attr= ['Master Indication attribute',
'Cluster attribute',
'Service ID List attribute',
'Service Descriptor attribute',
'NAN Connection Capability attribute',
'WLAN Infrastructure attribute',
'P2P Operation attribute',
'IBSS attribute',
'Mesh attribute',
'Further NAN Service Discovery attribute',
'Further Availability Map attribute',
'Country Code attribute',
'Ranging attribute',
'Cluster Discovery attribute1',
'Service Descriptor Extension attribute',
'Device Capability',
'NDP attribute',
'Reserved (NMSG attribute)',
'NAN Availability',
'NDC attribute',
'NDL attribute',
'NDL QoS attribute',
'Reserved (Multicast Schedule attribute)',
'Unaligned Schedule attribute',
'Reserved (Paging attribute - Unicast)',
'Reserved (Paging attribute - Multicast)',
'Ranging Information attribute',
'Ranging Setup attribute',
'FTM Ranging Report attribute',
'Element Container attribute',
'Extended WLAN Infrastructure attribute',
'Extended P2P Operation attribute',
'Extended IBSS attribute',
'Extended Mesh attribute',
'Cipher Suite Info attribute',
'Security Context Info attribute',
'Shared-Key Descriptor attribute',
'Reserved (Multicast Schedule Change attribute)',
'Reserved (Multicast Schedule Owner Change attribute)',
'Public Availability attribute',
'Subscribe Service ID List attribute']
attrIDs = list(enumerate(attr))
attrIDs.append((int(0xdd),'Vendor Specific attribute'))
actionSubs = list(enumerate(actsubtype))

def getsubtype(octet):
    for i in actionSubs:
        if "{:02x}".format(i[0]) == octet:
            return i[1]
def parseNan(data):
    match = False
    for i in attrIDs:
        #print "{:02x}".format(id[0]), data[0:2]
        if "{:02x}".format(i[0]) in data[0:2] :
            print i[1]
            match = True
    if not match:
        print data
    try:
        length = int(data[2:4],16)  #actually 2 octets [2:6] bigEndian maybe though
        print 'length: {} \trawData: {}'.format(length,data[6:(length*2)+6])
        #dict with all the fields - defs as tuples
        parseNan(data[6+(length*2):])
    except Exception:
        #tb.print_exc()
        pass

#nan = rdpcap('/home/hp/Desktop/nan/actiononly.pcapng')
nan = rdpcap('/home/hp/Desktop/nan/pi-phoneFail-phonePublisher.pcapng')
#nan = rdpcap('actiononly.pcapng')
for packet in nan:
    data = str(packet).encode('HEX')
    if '09506f9a18' in data:
        nandata = data.split('506f9a18')[1]
        print 'action ', getsubtype(nandata[0:2])
        parseNan(nandata[2:])
    elif '09506f9a13' in data:
        nandata = data.split('506f9a13')[1]
        print 'serviceDis ' ,  nandata
        parseNan(nandata)
    elif '04506f9a18' in data:
        nandata = data.split('506f9a18')[1]
        print 'action ', getsubtype(nandata[0:2])
        parseNan(nandata[2:])
    elif '04506f9a13' in data:
        nandata = data.split('506f9a13')[1]
        print 'serviceDis ' ,  nandata
        parseNan(nandata)
    elif re.search('dd\w{2}506f9a13',data):
        nandata = data.split('506f9a13')[1]
        print 'Info Element ' ,  nandata
        parseNan(nandata)
    print '#'*20, 'end of packet'


