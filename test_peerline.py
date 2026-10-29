import asyncio
import json
import ssl
import struct
import tempfile
import unittest
from pathlib import Path
from peerline import create_identity,context,verify_peer,encode_message,receive,terminal_safe

class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_unicode_and_fragmented_delivery(self):
        reader=asyncio.StreamReader();payload=encode_message('Hello 👋',0)
        async def feed():
            for byte in payload:reader.feed_data(bytes([byte]));await asyncio.sleep(0)
        task=asyncio.create_task(feed())
        self.assertEqual(await receive(reader,0),'Hello 👋');await task
    async def test_invalid_frames(self):
        for packet in (struct.pack('!I',999999),encode_message('hi',2),struct.pack('!I',2)+b'[]'):
            reader=asyncio.StreamReader();reader.feed_data(packet);reader.feed_eof()
            with self.assertRaises(ValueError):await receive(reader,0)
    def test_empty_and_oversize_messages(self):
        for text in ('',' '*10,'x'*16001):
            with self.assertRaises(ValueError):encode_message(text,0)
    def test_terminal_controls(self):self.assertNotIn('\x1b',terminal_safe('\x1b[31mhello'))

class MutualTLSTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        loop=asyncio.get_running_loop()
        self.previous_handler=loop.get_exception_handler()
        def expected_tls_rejection(loop,ctx):
            if ctx.get('message')=='Error on transport creation for incoming connection' and isinstance(ctx.get('exception'),(ConnectionResetError,ssl.SSLError)):
                return
            loop.default_exception_handler(ctx)
        loop.set_exception_handler(expected_tls_rejection)
        for name in ('alice','bob','mallory'):create_identity(self.root/name)
    async def asyncTearDown(self):
        asyncio.get_running_loop().set_exception_handler(self.previous_handler)
        self.tmp.cleanup()
    async def test_mutual_auth_and_round_trip(self):
        completed=asyncio.get_running_loop().create_future()
        async def server_side(reader,writer):
            try:
                verify_peer(writer,self.root/'alice/public.pem')
                message=await receive(reader,0);writer.write(encode_message('ack: '+message,0));await writer.drain()
                completed.set_result(message)
            except Exception as e:completed.set_exception(e)
            finally:writer.close();await writer.wait_closed()
        server=await asyncio.start_server(server_side,'127.0.0.1',0,ssl=context(self.root/'bob',self.root/'alice/public.pem',True))
        async with server:
            port=server.sockets[0].getsockname()[1]
            r,w=await asyncio.open_connection('127.0.0.1',port,ssl=context(self.root/'alice',self.root/'bob/public.pem'),server_hostname=None)
            verify_peer(w,self.root/'bob/public.pem');w.write(encode_message('hello',0));await w.drain()
            self.assertEqual(await receive(r,0),'ack: hello');self.assertEqual(await completed,'hello')
            w.close();await w.wait_closed()
    async def test_wrong_server_certificate_rejected(self):
        async def callback(r,w):w.close()
        server=await asyncio.start_server(callback,'127.0.0.1',0,ssl=context(self.root/'bob',self.root/'alice/public.pem',True))
        async with server:
            with self.assertRaises(ssl.SSLCertVerificationError):
                await asyncio.open_connection('127.0.0.1',server.sockets[0].getsockname()[1],ssl=context(self.root/'alice',self.root/'mallory/public.pem'),server_hostname=None)
    async def test_untrusted_client_rejected(self):
        accepted=[]
        async def callback(r,w):accepted.append(True);w.close()
        server=await asyncio.start_server(callback,'127.0.0.1',0,ssl=context(self.root/'bob',self.root/'alice/public.pem',True))
        async with server:
            writer=None
            try:
                reader,writer=await asyncio.open_connection('127.0.0.1',server.sockets[0].getsockname()[1],ssl=context(self.root/'mallory',self.root/'bob/public.pem'),server_hostname=None)
                writer.write(encode_message('unauthorized',0));await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.read(1),timeout=3),b'')
            except (ssl.SSLError,ConnectionResetError):pass
            finally:
                if writer:
                    writer.close()
                    try:await writer.wait_closed()
                    except (ssl.SSLError,ConnectionResetError):pass
            self.assertEqual(accepted,[])
if __name__=='__main__':unittest.main()

