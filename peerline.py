"""Peerline: direct, mutually authenticated TLS 1.3 terminal messaging."""
import argparse
import asyncio
import hashlib
import json
import os
import ssl
import struct
import subprocess
import sys
from pathlib import Path

MAX_FRAME=65536
MAX_TEXT=16000

def fingerprint(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path(pem).read_text())).hexdigest()


def create_identity(directory):
    directory=Path(directory)
    if directory.exists():raise ValueError('Identity directory already exists; refusing to overwrite keys.')
    directory.mkdir(mode=0o700,parents=True)
    key=directory/'private.key';cert=directory/'public.pem'
    # Restrict creation permissions too, rather than only chmod after writing.
    previous=os.umask(0o077)
    try:
        subprocess.run(['openssl','req','-x509','-newkey','ed25519','-nodes','-days','365',
                        '-keyout',str(key),'-out',str(cert),'-subj','/CN=Peerline Identity',
                        '-addext','basicConstraints=critical,CA:FALSE',
                        '-addext','keyUsage=critical,digitalSignature',
                        '-addext','extendedKeyUsage=serverAuth,clientAuth',
                        '-addext','subjectKeyIdentifier=hash',
                        '-addext','authorityKeyIdentifier=keyid:always'],check=True,capture_output=True)
    finally:os.umask(previous)
    return fingerprint(cert)


def context(identity,trust,server=False):
    identity=Path(identity)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    if not server:ctx.check_hostname=False # Identity is an explicitly exchanged certificate, not DNS.
    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.load_cert_chain(str(identity/'public.pem'),str(identity/'private.key'))
    ctx.load_verify_locations(cafile=str(trust))
    return ctx


def verify_peer(writer,trust):
    actual=hashlib.sha256(writer.get_extra_info('ssl_object').getpeercert(binary_form=True)).hexdigest()
    if actual!=fingerprint(trust):raise ValueError('Peer certificate does not match the trusted fingerprint.')
    return actual


def encode_message(text,sequence):
    if not isinstance(text,str) or not text.strip() or len(text.encode())>MAX_TEXT:
        raise ValueError('Message must contain 1–16,000 UTF-8 bytes.')
    if type(sequence) is not int or sequence<0:raise ValueError('Invalid sequence')
    body=json.dumps({'version':1,'sequence':sequence,'text':text},ensure_ascii=False).encode()
    if len(body)>MAX_FRAME:raise ValueError('Encoded message too large')
    return struct.pack('!I',len(body))+body


async def receive(reader,expected):
    header=await reader.readexactly(4)
    size=struct.unpack('!I',header)[0]
    if not 1<=size<=MAX_FRAME:raise ValueError('Frame size is out of bounds')
    body=await asyncio.wait_for(reader.readexactly(size),timeout=15)
    message=json.loads(body)
    if not isinstance(message,dict) or message.get('version')!=1 or type(message.get('sequence')) is not int or message['sequence']!=expected:
        raise ValueError('Invalid protocol version or message sequence')
    text=message.get('text')
    if not isinstance(text,str) or not text.strip() or len(text.encode())>MAX_TEXT:raise ValueError('Invalid text payload')
    return text


def terminal_safe(text):
    # Strip terminal controls (including ANSI ESC) supplied by another peer.
    return ''.join(c if c.isprintable() or c=='\n' else ' ' for c in text)


async def chat(reader,writer,trust):
    peer=verify_peer(writer,trust)
    print(f'\nConnected · TLS 1.3 · peer SHA-256 {peer}\nMessages are not saved. Type /quit to leave.\n',flush=True)
    loop=asyncio.get_running_loop();queue=asyncio.Queue()
    def input_ready():
        line=sys.stdin.readline()
        queue.put_nowait(line)
        if not line:loop.remove_reader(sys.stdin.fileno())
    loop.add_reader(sys.stdin.fileno(),input_ready)
    async def sending():
        sequence=0
        while True:
            line=await queue.get()
            if not line or line.rstrip()=='/quit':return
            text=line.rstrip('\n')
            if not text.strip():continue
            try:payload=encode_message(text,sequence)
            except ValueError as e:print(f'Not sent: {e}',flush=True);continue
            writer.write(payload);await writer.drain();sequence+=1
    async def receiving():
        sequence=0
        while True:
            text=await receive(reader,sequence);sequence+=1
            print(f'\npeer › {terminal_safe(text)}',flush=True)
    tasks=[asyncio.create_task(sending()),asyncio.create_task(receiving())]
    try:
        done,pending=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            try:task.result()
            except asyncio.IncompleteReadError:print('\nPeer disconnected.',flush=True)
    finally:
        loop.remove_reader(sys.stdin.fileno())
        for task in tasks:task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        writer.close()
        try:await writer.wait_closed()
        except (OSError,ssl.SSLError):pass


async def run(args):
    if args.command=='connect':
        reader,writer=await asyncio.wait_for(asyncio.open_connection(args.host,args.port,ssl=context(args.identity,args.trust),server_hostname=None,ssl_handshake_timeout=10),timeout=15)
        await chat(reader,writer,args.trust)
    else:
        finished=asyncio.Event();busy=False
        async def accepted(reader,writer):
            nonlocal busy
            if busy:
                writer.close();return
            busy=True
            try:await chat(reader,writer,args.trust)
            except (ValueError,OSError,TimeoutError) as e:print(f'Connection ended: {e}',flush=True)
            finally:
                writer.close();finished.set()
        server=await asyncio.start_server(accepted,args.host,args.port,ssl=context(args.identity,args.trust,True),ssl_handshake_timeout=10)
        print(f'Listening on {args.host}:{args.port}. Trusted peer: {fingerprint(args.trust)}',flush=True)
        async with server:await finished.wait()


def main():
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest='command',required=True)
    new=commands.add_parser('identity');new.add_argument('directory')
    show=commands.add_parser('fingerprint');show.add_argument('certificate')
    for name in ('listen','connect'):
        p=commands.add_parser(name);p.add_argument('--identity',required=True);p.add_argument('--trust',required=True)
        p.add_argument('--host',default='127.0.0.1');p.add_argument('--port',type=int,default=8765)
    args=parser.parse_args()
    try:
        if args.command=='identity':print('Identity created. Share only public.pem. SHA-256:',create_identity(args.directory))
        elif args.command=='fingerprint':print(fingerprint(args.certificate))
        else:asyncio.run(run(args))
    except KeyboardInterrupt:print('\nDisconnected.')
    except (ValueError,OSError,TimeoutError,subprocess.CalledProcessError) as e:
        print(f'Peerline: {e}',file=sys.stderr);return 1
    return 0
if __name__=='__main__':sys.exit(main())
