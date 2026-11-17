#!/usr/bin/env python
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
#   keytab.py unit tests
#
#   The keytab fixtures below are built with plain struct.pack on purpose:
#   they are fixed byte streams, independent of the implementation under
#   test, so parsing and round-trip serialization are checked against the
#   format itself.
#
import os
import tempfile
import unittest
from binascii import unhexlify
from struct import pack
from types import SimpleNamespace

from impacket.krb5.keytab import Keytab, Enctype


REALM = b'CONTOSO.LOCAL'
COMPONENTS = [b'svc-account', b'host.contoso.local']
PRINCIPAL = 'svc-account/host.contoso.local@CONTOSO.LOCAL'

AES256_KEY = bytes(range(32))
AES128_KEY = bytes(range(16))
OLD_AES256_KEY = b'\xbb' * 32
RC4_KEY = b'\xaa' * 16
NEW_RC4_KEY = b'\xcc' * 16
DELETED_AES256_KEY = b'\xdd' * 32


def entry_0502(components, realm, name_type, timestamp, vno8, keytype, key, vno32=None, deleted=False):
    body = pack('!H', len(components))
    body += pack('!H', len(realm)) + realm
    for component in components:
        body += pack('!H', len(component)) + component
    body += pack('!L', name_type)
    body += pack('!L', timestamp)
    body += pack('!B', vno8)
    body += pack('!H', keytype) + pack('!H', len(key)) + key
    if vno32 is not None:
        body += pack('!L', vno32)
    size = -len(body) if deleted else len(body)
    return pack('!l', size) + body


def entry_0501(components, realm, timestamp, vno8, keytype, key, vno32=None):
    # 0x501: num_components includes the realm, no name_type field
    body = pack('!H', len(components) + 1)
    body += pack('!H', len(realm)) + realm
    for component in components:
        body += pack('!H', len(component)) + component
    body += pack('!L', timestamp)
    body += pack('!B', vno8)
    body += pack('!H', keytype) + pack('!H', len(key)) + key
    if vno32 is not None:
        body += pack('!L', vno32)
    return pack('!l', len(body)) + body


# 0x502 keytab holding several keys for the same principal with different
# enctypes and kvnos, plus a deleted entry
KEYTAB_0502 = pack('!H', 0x0502) + b''.join([
    entry_0502(COMPONENTS, REALM, 1, 0x66000000, 3, Enctype.AES256.value, AES256_KEY, vno32=3),
    entry_0502(COMPONENTS, REALM, 1, 0x66000000, 3, Enctype.AES128.value, AES128_KEY),
    entry_0502(COMPONENTS, REALM, 1, 0x66000000, 2, Enctype.RC4.value, RC4_KEY),
    # same enctype, older kvno, stored after the current one
    entry_0502(COMPONENTS, REALM, 1, 0x66000000, 1, Enctype.AES256.value, OLD_AES256_KEY, vno32=2),
    # same enctype, newer kvno, stored after the older one
    entry_0502(COMPONENTS, REALM, 1, 0x66000000, 4, Enctype.RC4.value, NEW_RC4_KEY),
    # deleted entry with the highest kvno of all - must never be selected
    entry_0502(COMPONENTS, REALM, 1, 0x66000000, 9, Enctype.AES256.value, DELETED_AES256_KEY, deleted=True),
])

# 0x501 keytab: num_components counts the realm, no name_type field
KEYTAB_0501 = pack('!H', 0x0501) + b''.join([
    entry_0501([b'svc-account'], REALM, 0x65000000, 7, Enctype.RC4.value, RC4_KEY, vno32=7),
    entry_0501([b'svc-account'], REALM, 0x65000000, 7, Enctype.AES128.value, AES128_KEY),
])


class Keytab0502Tests(unittest.TestCase):
    def setUp(self):
        self.keytab = Keytab(KEYTAB_0502)

    def test_parse_entries(self):
        self.assertEqual(len(self.keytab.entries), 6)
        entry = self.keytab.entries[0]
        self.assertEqual(entry.principal.prettyPrint(), b'svc-account/host.contoso.local@CONTOSO.LOCAL')
        self.assertEqual(entry.timestamp, 0x66000000)
        self.assertEqual(entry.keyblock['keytype'], Enctype.AES256.value)
        self.assertEqual(len(entry.keyblock['keyvalue']['data']), 32)

    def test_kvno32_preferred_over_vno8(self):
        self.assertEqual(self.keytab.entries[0].kvno, 3)
        # vno8 is 1 but the 32-bit kvno field says 2
        self.assertEqual(self.keytab.entries[3].kvno, 2)
        # no 32-bit kvno field, vno8 rules
        self.assertEqual(self.keytab.entries[1].kvno, 3)

    def test_deleted_entry_flagged(self):
        self.assertFalse(self.keytab.entries[0].deleted)
        self.assertTrue(self.keytab.entries[5].deleted)

    def test_getkey_prefers_enctype_preference(self):
        keyblock = self.keytab.getKey(PRINCIPAL)
        self.assertEqual(keyblock['keytype'], Enctype.AES256.value)

    def test_getkey_selects_highest_kvno(self):
        # the older AES256 key (kvno 2) is stored after the current one (kvno 3)
        keyblock = self.keytab.getKey(PRINCIPAL)
        self.assertEqual(keyblock['keyvalue']['data'], AES256_KEY)
        # the newer RC4 key (kvno 4) is stored after the older one (kvno 2)
        keyblock = self.keytab.getKey(PRINCIPAL, specificEncType=Enctype.RC4.value)
        self.assertEqual(keyblock['keyvalue']['data'], NEW_RC4_KEY)

    def test_getkey_skips_deleted_entries(self):
        # the deleted entry holds the highest kvno (9) of all AES256 keys
        keyblock = self.keytab.getKey(PRINCIPAL, specificEncType=Enctype.AES256.value)
        self.assertEqual(keyblock['keyvalue']['data'], AES256_KEY)

    def test_getkey_specific_enctype(self):
        keyblock = self.keytab.getKey(PRINCIPAL, specificEncType=Enctype.AES128.value)
        self.assertEqual(keyblock['keyvalue']['data'], AES128_KEY)

    def test_getkey_not_found(self):
        self.assertIsNone(self.keytab.getKey('nosuchuser@CONTOSO.LOCAL'))
        self.assertIsNone(self.keytab.getKey(PRINCIPAL, specificEncType=Enctype.DES3.value))

    def test_getkey_realm_matching(self):
        # ignoreRealm=True (default) matches on the principal part only
        self.assertIsNotNone(self.keytab.getKey('svc-account/host.contoso.local@OTHER.REALM'))
        # ignoreRealm=False requires the full principal to match
        self.assertIsNone(self.keytab.getKey('svc-account/host.contoso.local@OTHER.REALM', ignoreRealm=False))
        self.assertIsNotNone(self.keytab.getKey(PRINCIPAL, ignoreRealm=False))

    def test_roundtrip(self):
        self.assertEqual(self.keytab.getData(), KEYTAB_0502)


class Keytab0501Tests(unittest.TestCase):
    def setUp(self):
        self.keytab = Keytab(KEYTAB_0501)

    def test_version_preserved(self):
        self.assertEqual(self.keytab.file_format_version, 0x501)

    def test_parse_entries(self):
        # 0x501 has no name_type field; a parser assuming 0x502 would read the
        # timestamp as name_type and end up with a bogus keytype/key length
        self.assertEqual(len(self.keytab.entries), 2)
        entry = self.keytab.entries[0]
        self.assertEqual(entry.principal.components[0]['data'], b'svc-account')
        self.assertEqual(entry.principal.realm['data'], REALM)
        self.assertEqual(entry.timestamp, 0x65000000)
        self.assertEqual(entry.kvno, 7)
        self.assertEqual(entry.keyblock['keytype'], Enctype.RC4.value)
        self.assertEqual(entry.keyblock['keyvalue']['data'], RC4_KEY)
        self.assertEqual(self.keytab.entries[1].keyblock['keytype'], Enctype.AES128.value)
        self.assertEqual(len(self.keytab.entries[1].keyblock['keyvalue']['data']), 16)

    def test_getkey(self):
        keyblock = self.keytab.getKey('svc-account@CONTOSO.LOCAL', specificEncType=Enctype.RC4.value)
        self.assertEqual(keyblock['keyvalue']['data'], RC4_KEY)

    def test_roundtrip(self):
        self.assertEqual(self.keytab.getData(), KEYTAB_0501)


class LoadKeysFromKeytabTests(unittest.TestCase):
    def write_keytab(self, data):
        fd, path = tempfile.mkstemp(suffix='.keytab')
        os.write(fd, data)
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_aes_key_returned_as_hex_string(self):
        # psexec & co. hand options.aesKey to getKerberosTGT, which only
        # unhexlifies strings - a bytes value would be taken as a raw key
        # and blow up with a wrong key length
        path = self.write_keytab(KEYTAB_0502)
        options = SimpleNamespace(aesKey=None, hashes=None)
        Keytab.loadKeysFromKeytab(path, 'svc-account/host.contoso.local', 'CONTOSO.LOCAL', options)
        self.assertIsInstance(options.aesKey, str)
        self.assertEqual(unhexlify(options.aesKey), AES256_KEY)
        self.assertIsNone(options.hashes)

    def test_rc4_key_sets_hashes(self):
        keytab = pack('!H', 0x0502) + entry_0502(COMPONENTS, REALM, 1, 0x66000000, 1,
                                                 Enctype.RC4.value, RC4_KEY)
        path = self.write_keytab(keytab)
        options = SimpleNamespace(aesKey=None, hashes=None)
        Keytab.loadKeysFromKeytab(path, 'svc-account/host.contoso.local', 'CONTOSO.LOCAL', options)
        self.assertEqual(options.hashes, ':' + RC4_KEY.hex())
        self.assertIsNone(options.aesKey)

    def test_no_matching_principal(self):
        path = self.write_keytab(KEYTAB_0502)
        options = SimpleNamespace(aesKey=None, hashes=None)
        with self.assertLogs('impacket', level='WARNING'):
            Keytab.loadKeysFromKeytab(path, 'nosuchuser', 'CONTOSO.LOCAL', options)
        self.assertIsNone(options.aesKey)
        self.assertIsNone(options.hashes)


class TicketerKeytabTests(unittest.TestCase):
    def test_loadkeys_from_keytab_as_library(self):
        # ticketer.py's -spn/-keytab path used to reference a bare `options`
        # global, raising NameError when TICKETER is used as a library
        from examples.ticketer import TICKETER

        fd, path = tempfile.mkstemp(suffix='.keytab')
        os.write(fd, KEYTAB_0502)
        os.close(fd)
        self.addCleanup(os.unlink, path)

        options = SimpleNamespace(
            spn='svc-account/host.contoso.local',
            keytab=path,
            aesKey=None,
            nthash=None,
        )
        TICKETER('host.contoso.local', '', 'CONTOSO.LOCAL', options)
        self.assertIsInstance(options.aesKey, str)
        self.assertEqual(unhexlify(options.aesKey), AES256_KEY)

    def test_loadkeys_from_keytab_rc4(self):
        from examples.ticketer import TICKETER

        keytab = pack('!H', 0x0502) + entry_0502([b'svc', b'host.contoso.local'], REALM, 1, 0x66000000, 1,
                                                 Enctype.RC4.value, RC4_KEY)
        fd, path = tempfile.mkstemp(suffix='.keytab')
        os.write(fd, keytab)
        os.close(fd)
        self.addCleanup(os.unlink, path)

        options = SimpleNamespace(
            spn='svc/host.contoso.local',
            keytab=path,
            aesKey=None,
            nthash=None,
        )
        TICKETER('host.contoso.local', '', 'CONTOSO.LOCAL', options)
        self.assertEqual(options.nthash, RC4_KEY.hex())
        self.assertIsNone(options.aesKey)


if __name__ == '__main__':
    unittest.main()
