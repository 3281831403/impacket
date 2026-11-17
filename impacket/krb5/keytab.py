# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Kerberos Keytab format implementation
#   based on file format described at:
#   https://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/keytab.txt
#   As the ccache implementation, pretty lame and quick
#   Feel free to improve
#
# Author:
#   Patrick Welzel (@kcirtapw)
#
from datetime import datetime
from enum import Enum
from six import b

from struct import pack, unpack
from binascii import hexlify

from impacket.structure import Structure
from impacket import LOG


class Enctype(Enum):
    DES_CRC = 1
    DES_MD4 = 2
    DES_MD5 = 3
    DES3 = 16
    AES128 = 17
    AES256 = 18
    RC4 = 23


class CountedOctetString(Structure):
    """
    Note: This is very similar to the CountedOctetString structure in ccache, except:
      * `length` is uint16 instead of uint32
    """
    structure = (
        ('length','!H=0'),
        ('_data','_-data','self["length"]'),
        ('data',':'),
    )

    def prettyPrint(self, indent=''):
        return "%s%s" % (indent, hexlify(self['data']))


class KeyBlock(Structure):
    structure = (
        ('keytype','!H=0'),
        ('keyvalue',':', CountedOctetString),
    )

    def prettyKeytype(self):
        try:
            return Enctype(self['keytype']).name
        except:
            return "UNKNOWN:0x%x" % (self['keytype'])

    def hexlifiedValue(self):
        return hexlify(self['keyvalue']['data'])

    def prettyPrint(self):
        return "(%s)%s" % (self.prettyKeytype(), self.hexlifiedValue())


class KeytabPrincipal:
    """
    Note: This is very similar to the principal structure in ccache, except:
      * `num_components` is just uint16
      * using other size type for CountedOctetString
      * `name_type` field follows the other fields behind.

    The layout depends on the keytab file format version:
      * version 0x501: `num_components` counts the realm as well (i.e. the
        actual number of components is `num_components` - 1) and there is
        no `name_type` field.
      * version 0x502: `num_components` is the actual number of components
        and a uint32 `name_type` field follows the components.
    """
    class PrincipalHeader1(Structure):
        structure = (
            ('num_components', '!H=0'),
        )

    class PrincipalHeader2(Structure):
        structure = (
            ('name_type', '!L=0'),
        )

    def __init__(self, data=None, version=0x502):
        self.version = version
        self.components = []
        self.realm = None
        if data is not None:
            self.header1 = self.PrincipalHeader1(data)
            data = data[len(self.header1):]
            num_components = self.header1['num_components']
            if version == 0x501:
                # In the 0x501 format the realm is included in the count
                num_components -= 1
            self.realm = CountedOctetString(data)
            data = data[len(self.realm):]
            self.components = []
            for component in range(num_components):
                comp = CountedOctetString(data)
                data = data[len(comp):]
                self.components.append(comp)
            if version == 0x501:
                # No name_type field in the 0x501 format
                self.header2 = None
            else:
                self.header2 = self.PrincipalHeader2(data)
        else:
            self.header1 = self.PrincipalHeader1()
            self.header2 = None if version == 0x501 else self.PrincipalHeader2()

    def __len__(self):
        totalLen = len(self.header1) + len(self.realm)
        if self.header2 is not None:
            totalLen += len(self.header2)
        for i in self.components:
            totalLen += len(i)
        return totalLen

    def getData(self):
        if self.version == 0x501:
            # In the 0x501 format the realm is included in the count
            self.header1['num_components'] = len(self.components) + 1
        else:
            self.header1['num_components'] = len(self.components)
        data = self.header1.getData() + self.realm.getData()
        for component in self.components:
            data += component.getData()
        if self.header2 is not None:
            data += self.header2.getData()
        return data

    def __str__(self):
        return self.getData()

    def prettyPrint(self):
        principal = b''
        for component in self.components:
            if isinstance(component['data'], bytes) is not True:
                component = b(component['data'])
            else:
                component = component['data']
            principal += component + b'/'

        principal = principal[:-1]
        if isinstance(self.realm['data'], bytes):
            realm = self.realm['data']
        else:
            realm = b(self.realm['data'])
        principal += b'@' + realm
        return principal


class KeytabEntry:
    """
      keytab_entry {
          int32_t size;     /* negative when the entry was deleted */
          uint16_t num_components;    /* sub 1 if version 0x501 */  |\
          counted_octet_string realm;                               | \\  Keytab
          counted_octet_string components[num_components];          | /  Principal
          uint32_t name_type;   /* not present if version 0x501 */  |/
          uint32_t timestamp;
          uint8_t vno8;
          keyblock key;
          uint32_t vno; /* only present if >= 4 bytes left in entry */
      };
    """

    def __init__(self, data=None, version=0x502):
        self.version = version
        self.rest = b''
        if data is not None:
            raw_size = unpack('!l', data[:4])[0]
            self.size = abs(raw_size) + 4  # size field itself not included
            self.deleted = raw_size < 0
            body = data[4:self.size]
            self.principal = KeytabPrincipal(body, version)
            offset = len(self.principal)
            self.timestamp = unpack('!L', body[offset:offset + 4])[0]
            self.vno8 = body[offset + 4]
            offset += 5
            self.keyblock = KeyBlock(body[offset:])
            offset += len(self.keyblock)
            self.kvno = self.vno8
            self.rest = body[offset:]
            if len(self.rest) >= 4 and \
                    self.rest[:4] != b'\x00\x00\x00\x00':  # if "field" is present but all 0, it seems to gets ignored
                self.kvno = unpack('!L', self.rest[:4])[0]
        else:
            self.principal = KeytabPrincipal(version=version)
            self.timestamp = 0
            self.vno8 = 0
            self.keyblock = KeyBlock()
            self.kvno = 0
            self.deleted = True
            self.size = None

    def __len__(self):
        if self.size is not None:
            return self.size
        return len(self.getData())

    def getData(self):
        body = self.principal.getData()
        body += pack('!L', self.timestamp)
        body += pack('!B', self.vno8)
        body += self.keyblock.getData()
        body += self.rest
        size = len(body)
        if self.deleted:
            size = -size
        return pack('!l', size) + body

    def prettyPrint(self, indent=''):
        if self.deleted:
            return "%s[DELETED]" % indent
        else:
            text = "%sPrincipal: %s\n" % (indent, self.principal.prettyPrint())
            text += "%sTimestamp: %s" % (indent, datetime.fromtimestamp(self.timestamp).isoformat())
            text += "\tKVNO: %i\n" % self.kvno
            text += "%sKey: %s" % (indent, self.keyblock.prettyPrint())
            #if self.rest:
            #    text += "\n%sRest: %s" % (indent, self.rest)
            return text


class Keytab:

    GetkeyEnctypePreference = (Enctype.AES256.value,
                                 Enctype.AES128.value,
                                 Enctype.RC4.value)

    class MiniHeader(Structure):
        structure = (
            ('file_format_version', '!H=0x0502'),
        )

    def __init__(self, data=None):
        self.miniHeader = None
        self.entries = []
        self.file_format_version = 0x502
        if data is not None:
            self.miniHeader = self.MiniHeader(data)
            self.file_format_version = self.miniHeader['file_format_version']
            data = data[len(self.miniHeader):]
            while len(data):
                entry = KeytabEntry(data, self.file_format_version)
                self.entries.append(entry)
                data = data[len(entry):]

    def getData(self):
        miniHeader = self.MiniHeader()
        miniHeader['file_format_version'] = self.file_format_version
        data = miniHeader.getData()
        for entry in self.entries:
            data += entry.getData()
        return data

    def getKey(self, principal, specificEncType=None, ignoreRealm=True):
        principal = b(principal.upper())
        if ignoreRealm:
            principal = principal.split(b'@')[0]
        # enctype -> entry with the highest kvno seen so far
        matching_keys = {}
        for entry in self.entries:
            if entry.deleted:
                continue
            entry_principal = entry.principal.prettyPrint().upper()
            if entry_principal == principal or (ignoreRealm and entry_principal.split(b'@')[0] == principal):
                keytype = entry.keyblock["keytype"]
                if specificEncType is not None and keytype != specificEncType:
                    continue
                current = matching_keys.get(keytype)
                if current is None or entry.kvno > current.kvno:
                    matching_keys[keytype] = entry

        entry = None
        if specificEncType is not None:
            entry = matching_keys.get(specificEncType)
        else:
            for preference in self.GetkeyEnctypePreference:
                if preference in matching_keys:
                    entry = matching_keys[preference]
                    break

        if entry is not None:
            LOG.debug('Returning %s key for %s' % (entry.keyblock.prettyKeytype(),
                                                   entry.principal.prettyPrint()))
            return entry.keyblock

        LOG.debug('Principal %s not found in keytab' % principal)
        return None

    @classmethod
    def loadFile(cls, fileName):
        f = open(fileName, 'rb')
        data = f.read()
        f.close()
        return cls(data)

    @classmethod
    def loadKeysFromKeytab(cls, fileName, username, domain, options):
        keytab = Keytab.loadFile(fileName)
        keyblock = keytab.getKey("%s@%s" % (username, domain))
        if keyblock:
            if keyblock["keytype"] == Enctype.AES256.value or keyblock["keytype"] == Enctype.AES128.value:
                options.aesKey = keyblock.hexlifiedValue().decode('ascii')
            elif keyblock["keytype"] == Enctype.RC4.value:
                options.hashes = ':' + keyblock.hexlifiedValue().decode('ascii')
        else:
            LOG.warning("No matching key for SPN '%s' in given keytab found!", username)


    def saveFile(self, fileName):
        f = open(fileName, 'wb+')
        f.write(self.getData())
        f.close()

    def prettyPrint(self):
        print("Keytab Entries:")
        for i, entry in enumerate(self.entries):
            print(("[%d]" % i))
            print(entry.prettyPrint('\t'))
