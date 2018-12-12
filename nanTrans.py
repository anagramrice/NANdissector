from scapy.all import *
import traceback as tb
import re
import argparse
from infoelements import * 

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
        
#class Element(object):
#    def __init__(self,data):        
#        DeviceCapability.mapID(data[:2])
#        
#    @staticmethod
#    def info_elements(data):    
#        #802.11-2016 9.4.2 Elements
#        pass
        
class NanAvailability(object):
    def __init__(self,data):        
        NanAvailability.sequenceID(data[:2])
        NanAvailability.attr_ctrl(data[2:6])
        NanAvailability.availabilityEntry(data[6:])
        #Sequence ID 1, Attribute Ctrl 2, Availablity Entry List var
        
    @staticmethod
    def sequenceID(data):
        print ('\tNan Availability Sequence ID: {}'.format(int(data,16)))
        
    @staticmethod
    def attr_ctrl(data):
        #Field   Size(bits)     Value	
        #Map ID	4	Variable
        #	Identify the associated NAN Availability attribute
        #Committed Changed	1	0 or 1
        #	Set to 1 if Committed Availability changed, compared with last schedule advertisement; or any Conditional Availability is included.
        #	Set to 0, otherwise.
        #	This setting shall be the same for all the maps in a frame
        #Potential Changed	1	0 or 1
        #	Set to 1 if Potential Availability changed, compared with last schedule advertisement.
        #	Set to 0, otherwise.
        #	This setting shall be the same for all the maps in a frame
        #Public Availability Attribute Changed	1	0 or 1
        #	Set to 1 if Public Availability attribute changed, compared with last schedule advertisement.
        #	Set to 0, otherwise.
        #NDC Attribute Changed	1	0 or 1
        #	Set to 1 if NDC attribute changed, compared with last schedule advertisement.
        #	Set to 0, otherwise.
        #Reserved (Multicast Schedule Attribute Changed)	1	0 or 1
        #	Set to 1 if Multicast Schedule attribute changed, compared with last schedule advertisement.
        #	Set to 0, otherwise.
        #Reserved (Multicast Schedule Change Attribute Changed)	1	0 or 1
        #	Set to 1 if Multicast Schedule Change attribute changed, compared with last schedule advertisement.
        #	Set to 0, otherwise.
        #Reserved	6	Variable
        #    Reserved    
        attrbits = '{:016b}'.format(int(data,16))
        print ('\tNAN availability attribute Control')
        print ('\t\tmap id: {}'.format(attrbits[12:16]))
        print ('\t\tCommitted Availability : Changed' if attrbits[11] == '1' else '\t\tICommitted Availability : No Change' )
        print ('\t\tPotential Availability : Changed' if attrbits[10] == '1' else '\t\tPotential Availability : No Change' )
        print ('\t\tPublic Availability attribute: Changed' if attrbits[9] == '1' else '\t\tPublic Availability attribute: No Change' )
        print ('\t\tNDC Attribute: Changed' if attrbits[8] == '1' else '\t\tNDC Attribute: No Change' )
        print ('\t\tMulticast Schedule attribute: Changed' if attrbits[7] == '1' else '\t\tMulticast Schedule attribute: No Change' )
        print ('\t\tMulticast Schedule Change attribute: Changed' if attrbits[6] == '1' else '\t\tMulticast Schedule Change attribute: No Change' )
    @staticmethod
    def availabilityEntry(data):
        #Field	Size (octets)	Value	Description
        #Length	2	Variable	The length of the fields following the Length field in the attribute, in the number of octets.
        #Entry Control	2	Variable	See Table 80 for details.
        #Time Bitmap Control	2	Variable	Indicates the parameters associated with the subsequent Time Bitmap field. See Table 81 for details.
        #Time Bitmap Length	1	Variable	Indicate the length of the following Time Bitmap field, in the number of octets.
        #Time Bitmap	Variable	Variable	Each bit in the Time Bitmap corresponds to a time duration indicated by the value of Bit Duration subfield in the Time Bitmap Control field.
        #	When the bit is set to 1, the NAN Device indicates its availability for any NAN operations for the whole time duration associated with the bit.
        #	When the bit is set to 0, the NAN Device indicates unavailable for any NAN related operations for the time duration associated with the bit.
        #Band/Channel Entry List	Variable	Variable	The list of one or more Band or Channel Entries corresponding to this Availability Entry. See Table 82 for details.
        def entryCtrl(subdata):
            #0-2		Availability Type
            #	b0: 1, Committed; 0, otherwise;
            #	b1: 1, Potential; 0, otherwise.
            #	b2: 1, Conditional; 0, otherwise.
            #	000, 101, and 111 are reserved.
            #	Note - At least one of the three bits is set to 1 to be meaningful.
            #3-4		Usage Preference
            #	An integer ranging from 0 to 3, which represents the preference of being available in the associated FAWs. The preference is higher when the value is set larger.
            #	Note: It does not apply to Committed or Conditional FAWs.
            #5-7		Utilization
            #	Values 0 - 5 indicating proportion within the associated FAWs that are already utilized for other purposes quantized to 20%.
            #	Value 6 is reserved.
            #	Value 7 indicates unknown utilization.
            #8-11	Rx Nss
            #Indicate the max number of spatial streams the NAN Device can receive during the associated FAWs.
            #12		Time Bitmap Present
            #	1: Time Bitmap Control, Time Bitmap Length, and Time Bitmap fields are present
            #	0: Time Bitmap Control, Time Bitmap Length, and Time Bitmap are NOT present, and all NAN Slots are available
            #13-15	Reserved
            #	Reserved
            attrbits = '{:016b}'.format(int(subdata,16))
            print ('\t\t\tEntry Control Bits: {}'.format(attrbits))
        print ('\tNAN availability Entry:')
        print ('\t\tLength: '.format(int(data[:2],16)))
        entryCtrl(data[2:4])
        print ('\t\tTime Bitmap Control: {:016b}'.format(int(data[4:6],16)))
        try:
            bitmapLength = int(data[6:8],16)
            print ('\t\tTime Bitmap Length: {}'.format(bitmapLength))
            print ('\t\tTime Bitmap: {:b}'.format(int(data[8:8+(bitmapLength*2)],16)))
            #print len(data), 8+(bitmapLength*2)
            #print data[8+(bitmapLength*2):]    MAYBE issue look into it        
            print ('\t\tBand/Channel Entry list: {:08b}'.format(int(data[8+(bitmapLength*2):],16)))
        except ValueError:
            pass
        
class NDCattr(object):
    def __init__(self,data):        
        NDCattr.NDC_ID(data[:12])
        NDCattr.attr_ctrl(data[12:14])
        NDCattr.schedule_entry_list(data[14:])
        #NDC ID 6, Attribute Ctrl 1, Schedule Entry List var
        
    @staticmethod
    def NDC_ID(data):
        print ('\tNAN Data Cluster Address: {}'.format(data))
        
    @staticmethod
    def attr_ctrl(data):
        #b0	Selected NDC
        #	1: Selected NDC for a NDL Schedule;
        #	0: NDC included for the peer's information.
        #b1-b7	Reserved
        #	Reserved
        ctrlbits = '{:08b}'.format(int(data,16))
        print '\tAttribute Control'
        print ('\t\tSelected NDC for a NDL Schedule' if ctrlbits[7] == '1' else '\t\tNDC included for the peer\'s information' )
        
    @staticmethod
    def schedule_entry_list(data):
        #Map ID	1
        #	b0 - b3: Indicates the NAN Availability attribute associated with the subsequent schedule time bitmap.
        #	b4 - b7: reserved
        #Time Bitmap Control	2	Indicates the parameters associated with the subsequent Time Bitmap field. 
        #		0-2	Bit Duration
        #				0:16 TU
        #				1:32 TU
        #				2:64 TU
        #				3:128 TU
        #				4-7 reserved
        #				
        #		3-5	Period  --Indicate the repeat interval of the following bitmap. When set to 0, the indicated bitmap is not repeated.
        #		When set to non-zero, the repeat interval is:
        #				1: 128 TU
        #				2: 256 TU
        #				3: 512 TU
        #				4: 1024 TU
        #				5: 2048 TU
        #				6: 4096 TU
        #				7: 8192 TU
        #		6-14	Start Offset
        #			Start Offset is an integer. The time period specified by the Time Bitmap field starts at the 16 * Start Offset TUs after DW0.
        #			Note that the NAN Slots not covered by any Time Bitmap are assumed to be NOT available.
        #		15	Reserved
        #			Reserved
        #Time Bitmap Length	1	Indicate the length of the following Time Bitmap field, in the number of octets.
        #Time Bitmap			Variable	Indicates the time windows associated with the schedule
        print ('\tSchedule Entry')
        print ('\t\tMapID Indicates the NAN Availability attribute associated with the subsequent schedule time bitmap: {:08b}'.format(int(data[:2],16)))
        timebitCtrl = '{:016b}'.format(int(data[2:6],16))
        print ('\t\tTime Bitmap Control')
        print ('\t\t\tDuration: {}'.format(int(timebitCtrl[13:16],2)))
        print ('\t\t\tPeriod: {}'.format(int(timebitCtrl[10:13],2)))
        print ('\t\t\tStart Offset: {}'.format(int(timebitCtrl[1:10],2)))
        print ('\t\tTime Bitmap Length: {}'.format(int(data[6:8],16)))
        print ('\t\tTime Bitmap {}'.format(data[8:]))
        
class NDLattr(object):
    def __init__(self,data):        
        NDPattr.Dialog_Token(data[:2])
        NDPattr.Type_Status(data[2:4])
        NDPattr.ReasonCode(data[4:6])
        NDLattr.NDL_Ctrl(data[6:])
        #Dialog Token 1, Type and Status 1, Reason Code 1, NDL Ctrl 1, Reserved 1, Max Idle Period 2, Immutable Sched var
    @staticmethod    
    def NDL_Ctrl(data):
        #NDL Peer ID Present 1
        #	1: Indicates the NDL Peer ID field is included in the NDL attribute;
        #	0: otherwise
        #Immutable Schedule Present 1
        #	1: Indicates the Immutable Schedule Entry List is included in the NDL attribute;
        #	0: otherwise
        #NDC Attribute Present	1
        #	1: Indicates the NDC attribute associated with the NDL schedule is included in the same frame that carries the NDL attribute;
        #	0: otherwise
        #NDL QoS Attribute Present	1
        #	1: Indicates the NDL QoS attribute associated with the NDL schedule is included in the same frame that carries the NDL attribute;
        #	0: otherwise
        #Max Idle Period Present	1
        #	1: Indicates the Max Idle Period field is included in the NDL attribute;
        #	0: otherwise
        #NDL Type	1
        #	1: Reserved (Indicates P-NDL request/response or confirm)
        #	0: Indicates S-NDL
        #NDL Setup Reason	2
        #	00: NDP
        #	01: FSD using GAS
        #	10: reserved
        #	11: reserved
        ctrlbits = '{:08b}'.format(int(data[:2],16))
        print ('\tNDL Control')
        print ('\t\tNDL Peer ID Present: True' if ctrlbits[7] == '1' else '\t\tNDL Peer ID Present: False' )
        print ('\t\tImmutable Schedule Present: True' if ctrlbits[6] == '1' else '\t\tImmutable Schedule Present: False' )
        print ('\t\tNDC Attribute Present: True' if ctrlbits[5] == '1' else '\t\tNDC Attribute Present: False' )
        print ('\t\tNDL QoS Attribute Present: True' if ctrlbits[4] == '1' else '\t\tNDL QoS Attribute Present: False' )
        print ('\t\tMax Idle Period Present: True' if ctrlbits[3] == '1' else '\t\tMax Idle Period Present: False' )
        print ('\t\tReserved (Indicates P-NDL request/response or confirm)' if ctrlbits[2] == '1' else '\t\tIndicates S-NDL' )
        if ctrlbits[:2] == '00':
            print ('\t\tNDL Setup Reason: NDP')
        elif ctrlbits[:2] == '01':
            print ('\t\tNDL Setup Reason: FSD using GAS')
        else:
            print ('\t\tNDL Setup Reason: reserved')
        baseindex = 2
        if ctrlbits[7] == '1':
            NDLattr.NDL_PeerID(data[baseindex:baseindex+2])
        if ctrlbits[3] == '1':
            NDLattr.MaxIdlePeriod(data[baseindex:baseindex+4])
        if ctrlbits[6] == '1':
            NDLattr.ImmutableSched(data[baseindex:])
            
    @staticmethod    
    def NDL_PeerID(data):
        print '\tNDL PeerID'
        print '\t\tPeer ID:{}'.format(data)
    @staticmethod    
    def MaxIdlePeriod(data):
        print '\tMax Idle Period'
        print '\t\tIndicate a period of time in units of 1024TU during which the peer NAN device can refrain from transmitting over the NDL: {}'.format(int(data,16))
    @staticmethod    
    def ImmutableSched(data):
        print '\tImmutable Schedule'
        print '\t\tbitmap: {}'.format(data)
        
class NDLQoSattr(object):
    def __init__(self,data):        
        NDLQoSattr.MinTimeSlots(data[:2])
        NDLQoSattr.MaxLatency(data[2:])
    
    @staticmethod    
    def MinTimeSlots(data):
        print ('\t\tMinimum number of further available NAN Slots needed per DW interval (512 TU): {}'.format(int(data,16)) if int(data,16) != 0 else '\t\tMinimum time slot: No Preference' )
    @staticmethod    
    def MaxLatency(data):
        print ('\t\tMaximum allowed NAN Slots between every two non-contiguous NDL CRBs: {}'.format(int(data,16)) if int(data,16) != 65535 else '\t\tMinimum time slot: No Preference' )
        
        
class NDPattr(object):
    def __init__(self,data):        
        NDPattr.Dialog_Token(data[:2])
        NDPattr.Type_Status(data[2:4])
        NDPattr.ReasonCode(data[4:6])
        NDPattr.Initiator_IDI(data[6:18])
        NDPattr.NDP_ID(data[18:20])
        NDPattr.NDP_ctrl(data[20:])        
        #Dialog Token 1, Type and Status 1, Reason Code 1, Initiator IDI 6, NDP ID 1, NDP ctrl 1, Publish ID 1, Responder NDI 6, NDP Spec info var
    
    @staticmethod    
    def Dialog_Token(data):
        print '\tDialog Token id of transaction: {}'.format(data)
    @staticmethod    
    def Type_Status(data):
        typebits = '{:08b}'.format(int(data,16))[4:8]
        statusbits = '{:08b}'.format(int(data,16))[:4]
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
    @staticmethod    
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
    @staticmethod        
    def Initiator_IDI(data):
        print '\tInitiator MAC identifier'
        print '\t\t{}'.format(data)
    @staticmethod    
    def NDP_ID(data): 
        print '\tNDP ID: {}'.format(int(data,16))
    @staticmethod    
    def NDP_ctrl(data):
        #Confirm Required	b0	Valid for joint NDP/NDL setup and when the Type subfield is set to "Request". Reserved otherwise.
        #	0 - Confirm not required from NDP/NDL Initiator
        #	1 - Confirm required from NDP/NDL Initiator
        #Reserved	b1
        #	Reserved
        #Security Present	b2
        #	0 - the NDP does not require security.
        #	1 - the NDP requires security, and the associated security attributes are included in the same NAF.
        #Publish ID Present	b3
        #	0 - the Publish ID field is not present
        #	1 - the Publish ID field is present
        #Responder NDI Present	b4
        #	0 - the Responder NDI field is not present
        #	1 - the Responder NDI field is present
        #NDP Specific Info present	b5
        #	0 - the NDP Specific Info field is not present
        #	1 - the NDP Specific Info field is present
        #Reserved	b6-b7
        #	Reserved
        ctrlbits = '{:08b}'.format(int(data[:2],16))
        confirm = ctrlbits[7]
        reserved = ctrlbits[6]
        security = ctrlbits[5]
        pubid = ctrlbits[4]
        responderMAC = ctrlbits[3]
        ndpSpecInfo = ctrlbits[2]
        resesrved2 = ctrlbits[:2]
        base = 2
        print ('\tNDP Control')
        print ('\t\tConfirm NOT required from NDP/NDL Initiator' if int(confirm) == 0 else '\t\tConfirm required from NDP/NDL Initiator')
        print ('\t\tNDP does NOT require security.' if int(security) == 0 else '\t\tNDP requires security, and the associated security attributes are included in the same NAF.' )
        print ('\t\tPublish ID: False' if int(pubid) == 0 else '\t\tPublish ID: True' )
        print ('\t\tResponder NDI: False' if int(responderMAC) == 0 else '\t\tResponder NDI: True' )
        print ('\t\tNDP Specific Info: False' if int(ndpSpecInfo) == 0 else '\t\tNDP Specific Info: True' )
        if int(pubid):
            NDPattr.Publish_ID(data[base:base+2])
            base+=2
        if int(responderMAC):
            NDPattr.Responder_NDI(data[base:base+12])
            base+=12
        if int(ndpSpecInfo):    
            NDPattr.NDP_Spec_info(data[base:])
    @staticmethod    
    def Publish_ID(data):
        print ('\tPublish_ID: {}'.format(data))
    @staticmethod
    def Responder_NDI(data):
        print ('\tNDP Responder\'s Data Interface Address: {}'.format(data))
    @staticmethod
    def NDP_Spec_info(data):
        try:
            print ('\NDP Specific Info {}'.format(data.decode("hex")))
        except Exception:
            print ('\NDP Specific Info {}'.format(data))
            
            
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

                 
                 
##  __  __    _    ___ _   _    ____ ___  ____  _____  
## |  \/  |  / \  |_ _| \ | |  / ___/ _ \|  _ \| ____| 
## | |\/| | / _ \  | ||  \| | | |  | | | | | | |  _|   
## | |  | |/ ___ \ | || |\  | | |__| |_| | |_| | |___  
## |_|  |_/_/   \_\___|_| \_|  \____\___/|____/|_____| 
##                                                     


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