# This program is published under a GPLv2 license
# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Ryan Speers <ryan@rmspeers.com> 2011-2012
# Copyright (C) Roger Meyer <roger.meyer@csus.edu>: 2012-03-10 Added frames
# Copyright (C) Gabriel Potter <gabriel@potter.fr>: 2018
# Copyright (C) 2020 Dimitrios-Georgios Akestoridis <akestoridis@cmu.edu>
# Copyright (C) 2020 Henry-Joseph Audéoud <audeoudh@univ-grenoble-alpes.fr>
# This program is published under a GPLv2 license

"""
Wireless MAC according to IEEE 802.15.4.
"""

import struct

from scapy.compat import orb, chb
from scapy.error import warning
from scapy.config import conf

from scapy.data import DLT_IEEE802_15_4_WITHFCS, DLT_IEEE802_15_4_NOFCS
from scapy.packet import Packet, bind_layers
from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, \
    ConditionalField, Field, LELongField, PacketField, XByteField, \
    XLEIntField, XLEShortField, FCSField, Emph, FieldListField


# Utility Functions #

def panids_present(pkt):
    """Check if PAN IDs are present, according to Frame Control flags.

    Return two booleans, indicating if resp. dest and src PAN IDs are present.
    """
    if pkt.fcf_framever <= 0b01:
        if pkt.fcf_destaddrmode != 0b00 and pkt.fcf_srcaddrmode != 0b00:
            return True, not pkt.fcf_panidcompress
        else:
            return pkt.fcf_destaddrmode != 0b00, pkt.fcf_srcaddrmode != 0b00
    else:  # 2015 version
        # Table 7-2 from IEEE 802.15.4-2015
        key = pkt.fcf_destaddrmode, pkt.fcf_srcaddrmode, pkt.fcf_panidcompress
        if key == (0b00, 0b00, 0):
            return False, False
        elif key == (0b00, 0b00, 1):
            return True, False
        elif key == (0b10, 0b00, 0):
            return True, False
        elif key == (0b11, 0b00, 0):
            return True, False
        elif key == (0b10, 0b00, 1):
            return False, False
        elif key == (0b11, 0b00, 1):
            return False, False
        elif key == (0b00, 0b10, 0):
            return False, True
        elif key == (0b00, 0b11, 0):
            return False, True
        elif key == (0b00, 0b10, 1):
            return False, False
        elif key == (0b00, 0b11, 1):
            return False, False
        elif key == (0b11, 0b11, 0):
            return True, False
        elif key == (0b11, 0b11, 1):
            return False, False
        elif key == (0b10, 0b10, 0):
            return True, True
        elif key == (0b10, 0b11, 0):
            return True, True
        elif key == (0b11, 0b10, 0):
            return True, True
        elif key == (0b10, 0b11, 1):
            return True, False
        elif key == (0b11, 0b10, 1):
            return True, False
        elif key == (0b10, 0b10, 1):
            return True, False
        else:
            # Use of reserved address mode 0b01.  Unknown behaviour.  Return
            # something, but it'll certainly be wrong.
            return True, True


# Fields #

class dot15d4AddressField(Field):
    __slots__ = ["adjust", "length_of"]

    def __init__(self, name, default, length_of=None, fmt="<H", adjust=None):
        Field.__init__(self, name, default, fmt)
        self.length_of = length_of
        if adjust is not None:
            self.adjust = adjust
        else:
            self.adjust = lambda pkt, x: self.lengthFromAddrMode(pkt, x)

    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        if len(hex(self.i2m(pkt, x))) < 7:  # short address
            return hex(self.i2m(pkt, x))
        else:  # long address
            x = "%016x" % self.i2m(pkt, x)
            return ":".join(["%s%s" % (x[i], x[i + 1]) for i in range(0, len(x), 2)])  # noqa: E501

    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.adjust(pkt, self.length_of) == 2:
            return s + struct.pack(self.fmt[0] + "H", val)
        elif self.adjust(pkt, self.length_of) == 8:
            return s + struct.pack(self.fmt[0] + "Q", val)
        else:
            return s

    def getfield(self, pkt, s):
        if self.adjust(pkt, self.length_of) == 2:
            return s[2:], self.m2i(pkt, struct.unpack(self.fmt[0] + "H", s[:2])[0])  # noqa: E501
        elif self.adjust(pkt, self.length_of) == 8:
            return s[8:], self.m2i(pkt, struct.unpack(self.fmt[0] + "Q", s[:8])[0])  # noqa: E501
        else:
            raise Exception('impossible case')

    def lengthFromAddrMode(self, pkt, x):
        addrmode = 0
        pkttop = pkt.underlayer
        if pkttop is None:
            warning("No underlayer to guess address mode")
            return 0
        while True:
            try:
                addrmode = pkttop.getfieldval(x)
                break
            except Exception:
                if pkttop.underlayer is None:
                    break
                pkttop = pkttop.underlayer
        # print "Underlayer field value of", x, "is", addrmode
        if addrmode == 2:
            return 2
        elif addrmode == 3:
            return 8
        return 0


# Layers #

class Dot15d4(Packet):
    FRAME_TYPE = {
        0b000: "Beacon",
        0b001: "Data",
        0b010: "Ack",
        0b011: "Command",
        0b101: "Multipurpose",
        0b110: "Fragment",
        0b111: "Extended"
    }

    ADDRESSING_MODE = {
        0b00: "Not present",
        0b10: "Short",
        0b11: "Extended"
    }

    FRAME_VERSION = {
        0b00: "2003",
        0b01: "2006",
        0b10: "2015"
    }

    name = "802.15.4"
    fields_desc = [
        # Frame control
        BitField("fcf_reserved_1", 0, 1),
        BitEnumField("fcf_panidcompress", 0, 1, [False, True]),
        BitEnumField("fcf_ackreq", 0, 1, [False, True]),
        BitEnumField("fcf_pending", 0, 1, [False, True]),
        BitEnumField("fcf_security", 0, 1, [False, True]),
        Emph(BitEnumField("fcf_frametype", 0, 3, FRAME_TYPE)),
        BitEnumField("fcf_srcaddrmode", 0, 2, ADDRESSING_MODE),
        BitEnumField("fcf_framever", 0, 2, FRAME_VERSION),
        BitEnumField("fcf_destaddrmode", 2, 2, ADDRESSING_MODE),
        BitField("fcf_reserved_2", 0, 2),
        # Sequence number
        Emph(ByteField("seqnum", 1)),
    ]

    def mysummary(self):
        return self.sprintf(
            "802.15.4 %Dot15d4.fcf_frametype% "
            "(ackreq=%Dot15d4.fcf_ackreq% "
            "%Dot15d4.fcf_destaddrmode% -> %Dot15d4.fcf_srcaddrmode% "
            "Seq#%Dot15d4.seqnum%)")

    def answers(self, other):
        if isinstance(other, Dot15d4):
            if self.fcf_frametype == 2:  # ack
                # check for seqnum matching
                if self.seqnum != other.seqnum:
                    return 0
                # check that an ack was indeed requested
                elif other.fcf_ackreq == 1:
                    return 1
        return 0

    def post_build(self, p, pay):
        # This just forces destaddrmode to None for Ack frames.
        if self.fcf_frametype == 2 and self.fcf_destaddrmode != 0:
            self.fcf_destaddrmode = 0
            return p[:1] + \
                chb((self.fcf_srcaddrmode << 6) + (self.fcf_framever << 4)) \
                + p[2:] + pay
        else:
            return p + pay


class Dot15d4FCS(Dot15d4):
    """Drop-in replacement for Dot15d4 with support of FCS/checksum.

    This class expects a FCS/checksum in the input, and produces one in the
    output.  This provides the user flexibility, as many 802.15.4 interfaces
    will have an AUTO_CRC setting that will validate the FCS/CRC in firmware,
    and add it automatically when transmitting.
    """
    name = "802.15.4 - FCS"
    match_subclass = True
    fields_desc = Dot15d4.fields_desc + [FCSField("fcs", None, fmt="<H")]

    def compute_fcs(self, data):
        # Do a CRC-CCITT Kermit 16bit on the data given
        # Returns a CRC that is the FCS for the frame
        #  Implemented using pseudocode from: June 1986, Kermit Protocol Manual
        #  See also:
        #   http://regregex.bbcmicro.net/crc-catalogue.htm#crc.cat.kermit
        crc = 0
        for i in range(0, len(data)):
            c = orb(data[i])
            q = (crc ^ c) & 15  # Do low-order 4 bits
            crc = (crc // 16) ^ (q * 4225)
            q = (crc ^ (c // 16)) & 15  # And high 4 bits
            crc = (crc // 16) ^ (q * 4225)
        return struct.pack('<H', crc)  # return as bytes in little endian order

    def post_build(self, p, pay):
        # construct the packet with the FCS at the end
        p = Dot15d4.post_build(self, p, pay)
        if self.fcs is None:
            p = p[:-2]
            p = p + self.compute_fcs(p)
        return p


class Dot15d4AuxSecurityHeader(Packet):
    KEY_IDENTIFIER_MODE = {
        # Key is determined implicitly from the originator and recipient(s) of
        # the frame
        0: "Implicit",
        # Key is determined explicitly from the the 1-octet Key Index subfield
        # of the Key Identifier field
        1: "1oKeyIndex",
        # Key is determined explicitly from the 4-octet Key Source and the
        # 1-octet Key Index
        2: "4o-KeySource-1oKeyIndex",
        # Key is determined explicitly from the 8-octet Key Source and the
        # 1-octet Key Index
        3: "8o-KeySource-1oKeyIndex"
    }

    SEC_LEVEL = {
        0: "None",
        1: "MIC-32",
        2: "MIC-64",
        3: "MIC-128",
        4: "ENC",
        5: "ENC-MIC-32",
        6: "ENC-MIC-64",
        7: "ENC-MIC-128"
    }

    name = "802.15.4 Auxiliary Security Header"
    fields_desc = [
        BitField("sec_sc_reserved", 0, 3),
        BitEnumField("sec_sc_keyidmode", 0, 2, KEY_IDENTIFIER_MODE),
        BitEnumField("sec_sc_seclevel", 0, 3, SEC_LEVEL),
        XLEIntField("sec_framecounter", 0x00000000),
        # Key Identifier (variable length): identifies the key that is used for
        # cryptographic protection.
        # Key Source : length of sec_keyid_keysource varies btwn 0, 4, and 8
        # bytes depending on sec_sc_keyidmode.
        # 4 octets when sec_sc_keyidmode == 2
        ConditionalField(XLEIntField("sec_keyid_keysource", 0),
                         lambda pkt: pkt.getfieldval("sec_sc_keyidmode") == 2),
        # 8 octets when sec_sc_keyidmode == 3
        ConditionalField(LELongField("sec_keyid_keysource", 0),
                         lambda pkt: pkt.getfieldval("sec_sc_keyidmode") == 3),
        # Key Index (1 octet): allows unique identification of different keys
        # with the same originator.
        ConditionalField(XByteField("sec_keyid_keyindex", 0xFF),
                         lambda pkt: pkt.getfieldval("sec_sc_keyidmode") != 0),
    ]


class Dot15d4Ack(Packet):
    name = "802.15.4 Ack"
    fields_desc = []


class Dot15d4Data(Packet):
    name = "802.15.4 Data"
    fields_desc = [
        XLEShortField("dest_panid", 0xFFFF),
        dot15d4AddressField("dest_addr", 0xFFFF, length_of="fcf_destaddrmode"),
        ConditionalField(XLEShortField("src_panid", 0x0),
                         lambda pkt:panids_present(pkt.underlayer)[1]),
        ConditionalField(dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"),  # noqa: E501
                         lambda pkt:pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0),  # noqa: E501
        # Security field present if fcf_security == True
        ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),  # noqa: E501
                         lambda pkt:pkt.underlayer.getfieldval("fcf_security") is True),  # noqa: E501
    ]

    def guess_payload_class(self, payload):
        # TODO: See how it's done in wireshark:
        # https://github.com/wireshark/wireshark/blob/93c60b3b7c801dddd11d8c7f2a0ea4b7d02d700a/epan/dissectors/packet-ieee802154.c#L2061  # noqa: E501
        # it's too magic to me
        from scapy.layers.sixlowpan import SixLoWPAN
        from scapy.layers.zigbee import ZigbeeNWK
        if conf.dot15d4_protocol == "sixlowpan":
            return SixLoWPAN
        elif conf.dot15d4_protocol == "zigbee":
            return ZigbeeNWK
        else:
            if conf.dot15d4_protocol is None:
                _msg = "Please set conf.dot15d4_protocol to select a " + \
                       "802.15.4 protocol. Values must be in the list: "
            else:
                _msg = "Unknown conf.dot15d4_protocol value: must be in "
            warning(_msg +
                    "['sixlowpan', 'zigbee']" +
                    " Defaulting to SixLoWPAN")
            return SixLoWPAN

    def mysummary(self):
        return self.sprintf(
            "802.15.4 Data "
            "( %Dot15d4Data.src_panid%:%Dot15d4Data.src_addr% "
            "-> %Dot15d4Data.dest_panid%:%Dot15d4Data.dest_addr% )")


class Dot15d4Beacon(Packet):
    name = "802.15.4 Beacon"
    fields_desc = [
        XLEShortField("src_panid", 0x0),
        dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"),
        # Security field present if fcf_security == True
        ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),  # noqa: E501
                         lambda pkt:pkt.underlayer.getfieldval("fcf_security") is True),  # noqa: E501

        # Superframe spec field:
        BitField("sf_sforder", 15, 4),  # not used by ZigBee
        BitField("sf_beaconorder", 15, 4),  # not used by ZigBee
        BitEnumField("sf_assocpermit", 0, 1, [False, True]),
        BitEnumField("sf_pancoord", 0, 1, [False, True]),
        BitField("sf_reserved", 0, 1),  # not used by ZigBee
        BitEnumField("sf_battlifeextend", 0, 1, [False, True]),  # not used by ZigBee  # noqa: E501
        BitField("sf_finalcapslot", 15, 4),  # not used by ZigBee

        # GTS Fields
        #  GTS Specification (1 byte)
        BitEnumField("gts_spec_permit", 1, 1, [False, True]),  # GTS spec bit 7, true=1 iff PAN cord is accepting GTS requests  # noqa: E501
        BitField("gts_spec_reserved", 0, 4),  # GTS spec bits 3-6
        BitField("gts_spec_desccount", 0, 3),  # GTS spec bits 0-2
        #  GTS Directions (0 or 1 byte)
        ConditionalField(BitField("gts_dir_reserved", 0, 1), lambda pkt:pkt.getfieldval("gts_spec_desccount") != 0),  # noqa: E501
        ConditionalField(BitField("gts_dir_mask", 0, 7), lambda pkt:pkt.getfieldval("gts_spec_desccount") != 0),  # noqa: E501
        #  GTS List (variable size)
        # TODO add a Packet/FieldListField tied to 3bytes per count in gts_spec_desccount  # noqa: E501

        # Pending Address Fields:
        #  Pending Address Specification (1 byte)
        BitField("pa_reserved_1", 0, 1),
        BitField("pa_num_long", 0, 3),  # number of long addresses pending
        BitField("pa_reserved_2", 0, 1),
        BitField("pa_num_short", 0, 3),  # number of short addresses pending
        #  Address List (var length)
        FieldListField("pa_short_addresses", [],
                       XLEShortField("", 0x0000),
                       count_from=lambda pkt: pkt.pa_num_short),
        FieldListField("pa_long_addresses", [],
                       dot15d4AddressField("", 0, adjust=lambda pkt, x: 8),
                       count_from=lambda pkt: pkt.pa_num_long),
        # TODO beacon payload
    ]

    def mysummary(self):
        return self.sprintf(
            "802.15.4 Beacon "
            "( %Dot15d4Beacon.src_panid%:%Dot15d4Beacon.src_addr% "
            "assocPermit %Dot15d4Beacon.sf_assocpermit% "
            "panCoord %Dot15d4Beacon.sf_pancoord%)")


class Dot15d4Cmd(Packet):
    COMMAND_IDS = {
        1: "AssocReq",  # Association request
        2: "AssocResp",  # Association response
        3: "DisassocNotify",  # Disassociation notification
        4: "DataReq",  # Data request
        5: "PANIDConflictNotify",  # PAN ID conflict notification
        6: "OrphanNotify",  # Orphan notification
        7: "BeaconReq",  # Beacon request
        8: "CoordRealign",  # coordinator realignment
        9: "GTSReq"  # GTS request
        # 0x0a - 0xff reserved
    }

    name = "802.15.4 Command"
    fields_desc = [
        XLEShortField("dest_panid", 0xFFFF),
        # Users should correctly set the dest_addr field. By default is 0x0 for construction to work.  # noqa: E501
        dot15d4AddressField("dest_addr", 0x0, length_of="fcf_destaddrmode"),
        ConditionalField(XLEShortField("src_panid", 0x0),
                         lambda pkt:panids_present(pkt.underlayer)[1]),
        ConditionalField(dot15d4AddressField("src_addr", None,
                         length_of="fcf_srcaddrmode"),
                         lambda pkt:pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0),  # noqa: E501
        # Security field present if fcf_security == True
        ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),  # noqa: E501
                         lambda pkt:pkt.underlayer.getfieldval("fcf_security") is True),  # noqa: E501
        ByteEnumField("cmd_id", 0, COMMAND_IDS),
    ]

    def mysummary(self):
        return self.sprintf(
            "802.15.4 Command %Dot15d4Cmd.cmd_id% "
            "( %Dot15d.src_panid%:%Dot15d4.src_addr% "
            "-> %Dot15d4.dest_panid%:%Dot15d4.dest_addr% )")


class Dot15d4CmdCoordRealign(Packet):
    name = "802.15.4 Coordinator Realign Command"
    fields_desc = [
        # PAN Identifier (2 octets)
        XLEShortField("panid", 0xFFFF),
        # Coordinator Short Address (2 octets)
        XLEShortField("coord_address", 0x0000),
        # Logical Channel (1 octet): the logical channel that the coordinator
        # intends to use for all future communications
        ByteField("channel", 0),
        # Short Address (2 octets)
        XLEShortField("dev_address", 0xFFFF),
    ]

    def mysummary(self):
        return self.sprintf(
            "802.15.4 Coordinator Realign Payload "
            "( PAN ID: %Dot15dCmdCoordRealign.pan_id% "
            "channel %Dot15d4CmdCoordRealign.channel% )")

    def guess_payload_class(self, payload):
        if len(payload) == 1:
            return Dot15d4CmdCoordRealignPage
        else:
            return Packet.guess_payload_class(self, payload)


class Dot15d4CmdCoordRealignPage(Packet):
    name = "802.15.4 Coordinator Realign Page"
    fields_desc = [
        ByteField("channel_page", 0),
    ]


class Dot15d4CmdAssocReq(Packet):
    name = "802.15.4 Association Request Command"
    fields_desc = [
        BitField("allocate_address", 0, 1),  # Allocate Address
        BitField("security_capability", 0, 1),  # Security Capability
        BitField("reserved2", 0, 1),  # bit 5 is reserved
        BitField("reserved1", 0, 1),  # bit 4 is reserved
        BitField("receiver_on_when_idle", 0, 1),  # Receiver On When Idle
        BitField("power_source", 0, 1),  # Power Source
        BitField("device_type", 0, 1),  # Device Type
        BitField("alternate_pan_coordinator", 0, 1),  # Alternate PAN Coord.
    ]

    def mysummary(self):
        return self.sprintf(
            "802.15.4 Association Request Command "
            "( Alt PAN Coord: %Dot15d4CmdAssocReq.alternate_pan_coordinator% "
            "Device Type: %Dot15d4CmdAssocReq.device_type% )")


class Dot15d4CmdAssocResp(Packet):
    ASSOCIATION_STATUS = {
        0x00: 'successful',
        0x01: 'PAN_at_capacity',
        0x02: 'PAN_access_denied'
        # 0x03 - 0x7f == Reserved
        # 0x80 - 0xff == Reserved for MAC primitive enumeration values
    }

    name = "802.15.4 Association Response Command"
    fields_desc = [
        # Address assigned to device from coordinator (0xFFFF == none)
        XLEShortField("short_address", 0xFFFF),
        ByteEnumField("association_status", 0x00, ASSOCIATION_STATUS),
    ]

    def mysummary(self):
        return self.sprintf(
            "802.15.4 Association Response Command"
            "( Association Status: %Dot15d4CmdAssocResp.association_status% "
            "Assigned Address: %Dot15d4CmdAssocResp.short_address% )")


class Dot15d4CmdDisassociation(Packet):
    DIASSOCIATION_REASON = {
        0x01: 'coord_wishes_device_to_leave',
        0x02: 'device_wishes_to_leave'
        # 0x03 - 0x7f == Reserved
        # 0x80 - 0xff == Reserved for MAC primitive enumeration values
    }

    name = "802.15.4 Disassociation Notification Command"
    fields_desc = [
        ByteEnumField("disassociation_reason", 0x02, DIASSOCIATION_REASON),
    ]

    def mysummary(self):
        return self.sprintf(
            "802.15.4 Disassociation Notification Command "
            "( Disassociation Reason %Dot15d4CmdDisassociation.disassociation_reason% )")  # noqa: E501


class Dot15d4CmdGTSReq(Packet):
    name = "802.15.4 GTS Request Command"
    fields_desc = [
        # GTS Characteristics field (1 octet)
        # Reserved (bits 6-7)
        BitField("reserved", 0, 2),
        # Characteristics Type (bit 5)
        BitField("charact_type", 0, 1),
        # GTS Direction (bit 4)
        BitField("gts_dir", 0, 1),
        # GTS Length (bits 0-3)
        BitField("gts_len", 0, 4),
    ]

    def mysummary(self):
        return self.sprintf(
            "802.15.4 GTS Request Command "
            "( %Dot15d4CmdGTSReq.gts_len% : %Dot15d4CmdGTSReq.gts_dir% )")


# PAN ID conflict notification command frame is not necessary, only Dot15d4Cmd with cmd_id = 5 ("PANIDConflictNotify")  # noqa: E501
# Orphan notification command not necessary, only Dot15d4Cmd with cmd_id = 6 ("OrphanNotify")  # noqa: E501

# Bindings #
bind_layers(Dot15d4, Dot15d4Beacon, fcf_frametype=0)
bind_layers(Dot15d4, Dot15d4Data, fcf_frametype=1)
bind_layers(Dot15d4, Dot15d4Ack, fcf_frametype=2)
bind_layers(Dot15d4, Dot15d4Cmd, fcf_frametype=3)
bind_layers(Dot15d4Cmd, Dot15d4CmdAssocReq, cmd_id=0x01)
bind_layers(Dot15d4Cmd, Dot15d4CmdAssocResp, cmd_id=0x02)
bind_layers(Dot15d4Cmd, Dot15d4CmdDisassociation, cmd_id=0x03)
bind_layers(Dot15d4Cmd, Dot15d4CmdCoordRealign, cmd_id=0x08)
bind_layers(Dot15d4Cmd, Dot15d4CmdGTSReq, cmd_id=0x09)

# DLT Types #
conf.l2types.register(DLT_IEEE802_15_4_WITHFCS, Dot15d4FCS)
conf.l2types.register(DLT_IEEE802_15_4_NOFCS, Dot15d4)
