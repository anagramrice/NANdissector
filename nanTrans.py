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
        DeviceCapability.mapID(data[:2])
        DeviceCapability.Committed_DW_Info(data[2:6])
        DeviceCapability.Supported_Bands(data[6:8])
        DeviceCapability.Operation_Mode(data[8:10])
        DeviceCapability.Number_of_Antennas(data[10:12])
        DeviceCapability.Max_Channel_Switch_Time(data[12:16])
        DeviceCapability.Capability(data[16:])
    @staticmethod
    def mapID(data):
        #b0: set to 1 to indicate the device capabilities only apply to the specified NAN Availability map. set to 0 to indicate the device capabilities apply to the device, when no NAN Availability map is included in the same frame, or apply to all NAN Availability maps included in the same frame.
        #b1-b4: indicate the NAN Availability map associated with the device capabilities; and reserved when b0 is set to 0.
        if '{:08b}'.format(int(data,16))[7] == 1:
            print '\tmapID==1 device capabilities only apply to the specified NAN Availability map'
        else:
            print '\tmapID==0 device capabilities apply to the device'
            
    @staticmethod
    def Committed_DW_Info(data):
        DW_fields = '{:016b}'.format(int(data,16))
        print '\tCommitted Discovery Window Info'
        #2.4 GHz DW b0-b2
        print '\t\t2.4GHz Discovery Window wake up 2^(n-1): {} [0 no wake up]'.format(DW_fields[13:16])
        #5 GHz DW b3-b5
        print '\t\t5GHz Discovery Window wake up 2^(n-1): {} [0 no wake up]'.format(DW_fields[10:13])
        # 2.4 GHz DW Overwrite b6-b9
        print '\t\t2.4GHz MapID {}'.format(DW_fields[6:10])
        #5 GHz DW Overwrite b10-b13
        print '\t\t5GHz MapID {} '.format(DW_fields[2:6])
        #Reserved b14-b15
        print '\t\tReserved'.format(DW_fields[:2])
        
    @staticmethod
    def Supported_Bands(data):
        #Bitmap of Band IDs
        #Bit 0: Reserved (for TV white spaces)
        #Bit 1: Sub-1 GHz (excluding TV white spaces)
        #Bit 2: 2.4 GHz
        #Bit 3: Reserved (for 3.6 GHz)
        #Bit 4: 4.9 and 5 GHz
        #Bit 5: Reserved (for 60 GHz)
        #Bit 6-7: Reserved
        bandbits = '{:08b}'.format(int(data,16))
        print '\tSupported_Bands'
        print '\t\tReserved: {}'.format(bandbits[7])
        print '\t\tSub-1 GHz: {}'.format(bandbits[6])
        print '\t\t2.4 GHz: {}'.format(bandbits[5])
        print '\t\tReserved (for 3.6 GHz): {}'.format(bandbits[4])
        print '\t\t4.9 and 5 GHz: {}'.format(bandbits[3])
        print '\t\tReserved (for 60 GHz): {}'.format(bandbits[2])
        print '\t\tReserved: {}'.format(bandbits[:2])
        
    @staticmethod
    def Operation_Mode(data):
        #PHY Mode	b0		1: VHT	0: HT only
        #VHT 80+80	b1		1: VHT 80+80 support	0: otherwise
        #VHT 160		b2		1: VHT 160 support	0: otherwise
        #Paging NDL Support	b3		1: P-NDL supported	0 P-NDL not supported
        #Reserved	b4-b7		Reserved	
        opbits = '{:08b}'.format(int(data,16))
        print '\tOperation_Mode'
        print ('\t\tPHY Mode: VHT' if opbits[7] == '1' else '\t\tPHY Mode: HT only' )
        print ('\t\tVHT 80+80: Supported' if opbits[6] == '1' else '\t\tVHT 80+80: Unsupported' )
        print ('\t\tVHT 160: Supported' if opbits[5] == '1' else '\t\tVHT 80+80: Unsupported' )
        print ('\t\tPaging NDL Support: Supported' if opbits[4] == '1' else '\t\tPaging NDL Support: Unsupported' )
        print '\t\tReserved {}'.format(opbits[:4])
        
    @staticmethod
    def Number_of_Antennas(data):
        #Bit 0-3: Number of TX antennas
        #Bit 4-7: Number of RX antennas
        #Value 0 indicates the information is not available.
        antbits = '{:08b}'.format(int(data,16))
        print '\tNumber of Antennas'
        print ('\t\tTX antennas: not available' if int(antbits[0:4],2) == 0 else '\t\tTX antennas: {}'.format(int(antbits[0:4],2)) )
        print ('\t\tRX antennas: not available' if int(antbits[4:],2) == 0 else '\t\tRX antennas: {}'.format(int(antbits[4:],2)) )
            
    @staticmethod
    def Max_Channel_Switch_Time(data):
        #Indicates max channel switch time in units of microseconds;
        #Value 0 indicates the information is not available.
        #Note: Max Channel Switch Time value should be the same across multiple Device Capability attributes included in a single frame.
        ChSwitchTime = int(data,16)
        print ('\tMax channel switch time: not available' if ChSwitchTime == 0 else '\tMax channel switch time (uS): {}'.format(ChSwitchTime))
        
    @staticmethod
    def Capability(data):
        #Bit 0 (DFS Master): Set to 1 indicates that the device is a DFS master device. Otherwise, set to 0.
        #Bit 1 (Extended Key ID): Set to 1 indicates that the device supports IEEE 802.11 extended key ID mechanism (refer to [1] section 9.4.2.25.4], otherwise, set to 0. If this bit is set to 0, the Key ID 0 shall be used.
        #Bit 2 (Simultaneous NDP data reception): Set to 0 to indicate that the NAN Device does not support to receive the data packets of NDPs belonging to the same NDI pair in more than one channel within any Committed FAW or ULW. The NAN Device's behavior when this bit is set to 1 is outside the scope of this specification.
        #Bit 3 to Bit 7: Reserved.
        capabilitybits = '{:08b}'.format(int(data,16))
        print '\tCapability'
        print ('\t\tDFS master device: True' if capabilitybits[7] == '1' else '\t\tDFS master device: False' )
        print ('\t\tDevice supports IEEE 802.11 extended key ID mechanism: True' if capabilitybits[6] == '1' else '\t\tDevice supports IEEE 802.11 extended key ID mechanism: False' )
        print ('\t\tSimultaneous NDP data reception: True' if capabilitybits[5] == '1' else '\t\tSimultaneous NDP data reception: False' )
        print ('\t\tReserved {}'.format(capabilitybits[:5]))
        
class Element(object):
    def __init__(self,data):        
        DeviceCapability.mapID(data[:2])
    @staticmethod
    def info_elements(data):    
        #802.11-2016 9.4.2 Elements
        pass
        
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
        NDPattr.Dialog_Token(data[:2])
        NDPattr.Type_Status(data[2:4])
        NDPattr.ReasonCode(data[4:6])
        NDPattr.Initiator_IDI(data[6:18])
        NDPattr.NDP_ID(data[18:20])
        NDPattr.NDP_ctrl(data[20:])        
        #Dialog Token 1, Type and Status 1, Reason Code 1, Initiator IDI 6, NDP ID 1, NDP ctrl 1, Publish ID 1, Responder NDI 6, NDP Spec info var
        
    def Dialog_Token(data):
        print '\tDialog Token id of transaction: {}'.format(data)
        
    def Type_Status(data):
        typebits = '{:08b}'.format(int(data,16))[:4]
        statusbits = '{:08b}'.format(int(data,16))[4:]
        type = int(typebits,2)
        status = int(statusbits,2)
        print '\tType and Status'
        if type == 0:        
            print ('\t\tType: Request')
        elif type == 1:
            print ('\t\tType: Response')
        elif type == 2:
            print ('\t\tType: Confirm')
        elif type == 3:
            print ('\t\tType: Security Install')
        elif type == 4:
            print ('\t\tType: Terminate')
        else:
            print ('\t\tType: Reserved')
        if status == 0:        
            print ('\t\tstatus: Continued')
        elif status == 1:
            print ('\t\tstatus: Accepted')
        elif status == 2:
            print ('\t\tstatus: Rejected')
        else:
            print ('\t\tstatus: Reserved')
        
    def ReasonCode(data):
        reasons = {0: ('Reserved', 'Reserved'),
1: ('UNSPECIFIED_REASON', 'Unspecified reason'),
2: ('RESOURCE_LIMITATION', 'Resource limitation'),
3: ('INVALID_PARAMETERS' , 'Invalid parameters'),
4: ('FTM_PARAMETERS_INCAPABLE', 'FTM parameters incapable'),
5:	('NO_MOVEMENT', 'No Movement'),
6:	('INVALID_AVAILABILITY', 'Invalid NAN Availability attribute'),
7: ('IMMUTABLE_UNACCEPTABLE', 'Immutable schedule unacceptable'),
8: ('SECURITY_POLICY', 'Rejected due to device/service security policy'),
9: ('QoS_UNACCEPTABLE', 'QoS requirements unacceptable'),
10: ('NDP_REJECTED', 'NDP request rejected by upper layer'),
11: ('NDL_UNACCEPTABLE', 'NDL schedule proposal unacceptable'),
12: ('RANGING_SCHEDULE_UNACCEPTABLE', 'Ranging schedule proposal unacceptable')}
        code = int(data,16)
        print '\tReason Field'
        try:
            print '\t\t{}'.format(reasons[code])
        except Exception:
            print '\t\tReserved'
            
    def Initiator_IDI(data):
        print '\tInitiator MAC identifier'
        print '\t\t{}'.format(data)
        
    def NDP_ID(data): 
        print '\tNDP ID: {}'.format(int(data,16))
        
    def NDP_ctrl(data):
        #Confirm Required	b0	Valid for joint NDP/NDL setup and when the Type subfield is set to “Request”. Reserved otherwise.
        #	0 – Confirm not required from NDP/NDL Initiator
        #	1 – Confirm required from NDP/NDL Initiator
        #Reserved	b1
        #	Reserved
        #Security Present	b2
        #	0 – the NDP does not require security.
        #	1 – the NDP requires security, and the associated security attributes are included in the same NAF.
        #Publish ID Present	b3
        #	0 – the Publish ID field is not present
        #	1 – the Publish ID field is present
        #Responder NDI Present	b4
        #	0 – the Responder NDI field is not present
        #	1 – the Responder NDI field is present
        #NDP Specific Info present	b5
        #	0 – the NDP Specific Info field is not present
        #	1 – the NDP Specific Info field is present
        #Reserved	b6-b7
        #	Reserved

        ctrlbits = '{:08b}'.format(int(data[:2],16))
        if pubid:
            NDPattr.Publish_ID(data[22:24])
        if response:
            NDPattr.Responder_NDI(data[24:12])
        NDPattr.NDP_Spec_info(data[12:16])
        
    def Publish_ID(data):
        pass
    def Responder_NDI(data):
        pass
    def NDP_Spec_info(data):
        pass
        
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
            try:
                length = int(data[2:4],16)  #actually 2 octets [2:6] bigEndian maybe though
                datapathSetup[i[1]](data[6:(length*2)+6])
            except KeyError:
                pass
            except Exception:
                raise                
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
    count = 1
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
        print '#'*20, 'end of packet', count
        count+=1


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