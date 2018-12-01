from scapy.all import *
import traceback as tb
import re
import argparse

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


class DeviceCapability(object):
    def __init__(self,data):
        mapID(data[:2])
        Committed_DW_Info(data[2:6])
        Supported_Bands(data[6:8])
        Operation_Mode(data[8:10])
        Number_of_Antennas(data[10:12])
        Max_Channel_Switch_Time(data[12:16])
        Capability(data[16:])
    @staticmethod
    def mapID(data):
        #b0: set to 1 to indicate the device capabilities only apply to the specified NAN Availability map. set to 0 to indicate the device capabilities apply to the device, when no NAN Availability map is included in the same frame, or apply to all NAN Availability maps included in the same frame.
        #b1-b4: indicate the NAN Availability map associated with the device capabilities; and reserved when b0 is set to 0.
        if '{:08b}'.format(int(data,16))[0] == 1:
            print 'mapID==1 device capabilities only apply to the specified NAN Availability map'
        else:
            print 'mapID==0 device capabilities only apply to the specified NAN Availability map'
    @staticmethod
    def Committed_DW_Info(data):
        pass
        #2.4 GHz DW b0-b2
        if '{:016b}'.format(int(data,16))[0:2] == 1:
        #5 GHz DW b3-b5
        # 2.4 GHz DW Overwrite b6-b9
        #5 GHz DW Overwrite b10-b13
        #Reserved b14-b15
        
        
        
class Element(object):
    def __init__(self,data):        
        pass
        #mapID 1, Elements var
        
class NanAvailability(object):
    def __init__(self,data):        
        pass
        #Sequence ID 1, Attribute Ctrl 2, Availablity Entry List va
        
class NDCattr(object):
    def __init__(self,data):        
        pass
        #NDC ID 6, Attribute Ctrl 1, Schedule Entry List var
        
class NDLattr(object):
    def __init__(self,data):        
        pass
        #Dialog Token 1, Type and Status 1, Reason Code 1, NDL Ctrl 1, Reserved 1, Max Idle Period 2, Immutable Sched var
        
class NDLQoSattr(object):
    def __init__(self,data):        
        pass
        #Minimum time slots 1,Maximum latency 2, Attribute ID 1, Length 2, Attribute Control 2, Starting Time 4, Duration 4,Duration 4, Period 4, Count Down 1, ULW Overwrite 1, ULW Control 0|1, Band ID var
        
class NDPattr(object):
    def __init__(self,data):        
        pass
        #Dialog Token 1, Type and Status 1, Reason Code 1, Initiator IDI 6, NDP ID 1, NDP ctrl 1, Publish ID 1, Responder NDI 6, NDP Spec info var
        
class UnalignedSched(object):
    def __init__(self,data):        
        pass
        #Attribute Control 2, Starting Time 4, Duration 4, Period 4,Count Down 1,ULW Control 0|1, Band ID var
        
datapathSetup = {'Device Capability' : DeviceCapability,
                 'Element Container attribute' : Element,
                 'NAN Availability' : NanAvailability,
                 'NDC attribute' : NDCattr,
                 'NDL attribute' : NDLattr,
                 'NDL QoS attribute' : NDLQoSattr,
                 'NDP attribute' : NDPattr,
                 'Unaligned Schedule attribute' : UnalignedSched}


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


def binPackets(nan, isPcap):
    for packet in nan:
        if isPcap:
            data = str(packet).encode('HEX')
        else:
            data = packet
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


class Cmdparse(object):
    def __init__(self):        
        self.parser = argparse.ArgumentParser(prefix_chars="-")        
        self.parser.add_argument("-f","-F","--fname",dest="fname", help="filename of either pcap hexdump of capture")
        # Initialize printer variables
        self._args = self.parser.parse_args()
        print self._args.fname
        if '.pcap' in self._args.fname[-7:]:
            nan = rdpcap(self._args.fname)
            isPcap = True
        else:
            nan = self._args.fname
            isPcap = False
        binPackets(nan, isPcap)
        

if __name__ == '__main__':
    Cmdparse()