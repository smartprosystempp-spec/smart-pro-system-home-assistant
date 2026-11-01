"""Fake Supervisor/Core websocket tests for the read-only HA auth readback."""
import base64
import hashlib
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'smart-pro-access-preflight'))
from ha_readback import read_ha_admin_users, AdminReadbackError

USER_ID = '0123456789abcdef0123456789abcdef'
TEST_TOKEN = 'NOT_A_REAL_SUPERVISOR_TOKEN_FOR_TEST_ONLY_0123456'


def server_frame(payload, opcode=1, mask=False, fragmented=False):
    if isinstance(payload, (dict, list)):
        payload = json.dumps(payload).encode()
    if isinstance(payload, str):
        payload = payload.encode()
    length = len(payload)
    header = bytes([(0 if fragmented else 128) | opcode, (128 if mask else 0) | length]) if length < 126 else bytes([(0 if fragmented else 128) | opcode, (128 if mask else 0) | 126]) + length.to_bytes(2, 'big')
    if mask:
        key = b'1234'
        return header + key + bytes(v ^ key[i % 4] for i, v in enumerate(payload))
    return header + payload


def user(**patch):
    u = {'id': USER_ID, 'is_active': True, 'is_owner': False, 'system_generated': False,
         'group_ids': ['system-admin'], 'name': 'CUSTOMER_NAME_SHOULD_NOT_RETURN',
         'username': 'CUSTOMER_USERNAME_SHOULD_NOT_RETURN', 'credentials': [{'secret': 'DO_NOT_RETURN'}]}
    u.update(patch)
    return u


class FakeSupervisorSocket:
    def __init__(self, *, users=None, broken_upgrade=False, mismatch_accept=False,
                 bad_challenge=False, bad_auth=False, wrong_id=False, denied=False,
                 ping=False, broken_result=None, masked_result=False, fragmented_result=False):
        self.buf = bytearray()
        self.phase = 0
        self.users = users if users is not None else [user()]
        self.broken_upgrade = broken_upgrade
        self.mismatch_accept = mismatch_accept
        self.bad_challenge = bad_challenge
        self.bad_auth = bad_auth
        self.wrong_id = wrong_id
        self.denied = denied
        self.ping = ping
        self.broken_result = broken_result
        self.masked_result = masked_result
        self.fragmented_result = fragmented_result
        self.outbound = []

    def __enter__(self): return self
    def __exit__(self, *args): return False
    def settimeout(self, timeout): pass
    def recv(self, n):
        if not self.buf: return b''
        chunk = bytes(self.buf[:n]); del self.buf[:n]
        return chunk

    def sendall(self, data):
        if self.phase == 0:
            self.phase = 1
            request = data.decode('ascii')
            assert request.startswith('GET /core/websocket HTTP/1.1\r\n')
            key = request.split('Sec-WebSocket-Key: ')[1].split('\r\n')[0]
            accept = base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            if self.mismatch_accept: accept = 'INVALID'
            status = '403 Forbidden' if self.broken_upgrade else '101 Switching Protocols'
            self.buf.extend((f'HTTP/1.1 {status}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n').encode())
            if self.bad_challenge:
                self.buf.extend(server_frame({'type':'wrong_challenge'}))
            else:
                self.buf.extend(server_frame({'type':'auth_required','ha_version':'2026.11.0'}))
        else:
            first = data[0] & 15
            assert (data[1] & 128) != 0, 'Client must mask websocket frames'
            length = data[1] & 127
            index = 2
            if length == 126:
                length = int.from_bytes(data[index:index+2], 'big'); index += 2
            key = data[index:index+4]; index += 4
            payload = bytes(v ^ key[i % 4] for i, v in enumerate(data[index:index+length]))
            if first == 10:
                self.outbound.append(('pong', payload))
                return
            packet = json.loads(payload)
            self.outbound.append(packet)
            if packet.get('type') == 'auth':
                self.buf.extend(server_frame({'type':'auth_invalid' if self.bad_auth else 'auth_ok'}))
            elif packet.get('type') == 'config/auth/list':
                if self.ping:
                    self.buf.extend(server_frame(b'PING', opcode=9))
                result = ({'type':'result','id':2 if self.wrong_id else 1,
                           'success':not self.denied,'result':self.users})
                data = self.broken_result if self.broken_result is not None else result
                self.buf.extend(server_frame(data, mask=self.masked_result, fragmented=self.fragmented_result))
            else: raise AssertionError('unexpected user creation or API command')


class ReadbackTests(unittest.TestCase):
    def run_fake(self, **kwargs):
        fake = FakeSupervisorSocket(**kwargs)
        response = read_ha_admin_users(supervisor_token=TEST_TOKEN, connect=lambda *args:fake)
        return response,fake

    def expect_failure(self, code, **kwargs):
        with self.assertRaises(AdminReadbackError) as err:
            self.run_fake(**kwargs)
        self.assertEqual(str(err.exception), code)

    def test_verified_admin_users_are_returned(self):
        users,client = self.run_fake()
        self.assertEqual(users,[{'id':USER_ID,'is_active':True,'is_owner':False,'system_generated':False,'group_ids':['system-admin']}])
        self.assertEqual(client.outbound[0]['access_token'], TEST_TOKEN)
        self.assertEqual(client.outbound[1], {'id':1,'type':'config/auth/list'})

    def test_discard_customer_identity_details(self):
        users,_ = self.run_fake()
        self.assertNotIn('username',users[0])
        self.assertNotIn('name',users[0])
        self.assertNotIn('credentials',users[0])

    def test_rejected_upgrade(self): self.expect_failure('upgrade_rejected', broken_upgrade=True)
    def test_mismatched_websocket_accept(self): self.expect_failure('invalid_websocket_accept', mismatch_accept=True)
    def test_missing_auth_challenge(self): self.expect_failure('auth_challenge_missing', bad_challenge=True)
    def test_auth_invalid(self): self.expect_failure('ha_auth_failed', bad_auth=True)
    def test_wrong_response_id(self): self.expect_failure('ha_user_list_denied', wrong_id=True)
    def test_denied_user_list(self): self.expect_failure('ha_user_list_denied', denied=True)
    def test_masked_server_data(self): self.expect_failure('server_frame_masked', masked_result=True)
    def test_fragmented_server_data(self): self.expect_failure('fragmented_frame_rejected', fragmented_result=True)
    def test_nonjson_response(self): self.expect_failure('invalid_ha_json', broken_result='notjson')
    def test_wrong_response_type(self): self.expect_failure('invalid_ha_message', broken_result=['not','a','dict'])
    def test_empty_user_list(self): self.expect_failure('invalid_user_collection', users=[])
    def test_duplicate_identity_from_ha(self): self.expect_failure('invalid_or_duplicate_user_id', users=[user(),user()])
    def test_missing_groups(self): self.expect_failure('invalid_user_groups', users=[user(group_ids=None)])
    def test_incomplete_user_boolean(self): self.expect_failure('incomplete_user_flags', users=[user(is_owner='false')])
    def test_ping_pong(self):
        u,s = self.run_fake(ping=True)
        self.assertEqual(len(u), 1)
        self.assertIn(('pong',b'PING'), s.outbound)
    def test_short_local_token_is_denied(self):
        with self.assertRaisesRegex(AdminReadbackError,'local_ha_token_unavailable'):
            read_ha_admin_users(supervisor_token='short',connect=lambda *args: None)
    def test_no_token_is_denied(self):
        with self.assertRaisesRegex(AdminReadbackError,'local_ha_token_unavailable'):
            read_ha_admin_users(supervisor_token='',connect=lambda *args: None)
    def test_invalid_timeout_is_denied(self):
        with self.assertRaisesRegex(AdminReadbackError,'invalid_timeout'):
            read_ha_admin_users(supervisor_token=TEST_TOKEN,timeout=100)
    def test_connection_errors_are_redacted(self):
        def error(*args): raise OSError('SECRET_FROM_CONNECTION_NOT_PRINTABLE')
        with self.assertRaises(AdminReadbackError) as err:
            read_ha_admin_users(supervisor_token=TEST_TOKEN,connect=error)
        self.assertEqual(str(err.exception),'ha_connection_failed')

if __name__ == '__main__': unittest.main()
