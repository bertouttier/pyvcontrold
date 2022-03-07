import asyncio
import logging
from urllib.parse import urlparse
from async_timeout import timeout
import serial
from serial_asyncio import create_serial_connection
from scapy.packet import Raw

from .vpackets import *

logger = logging.getLogger(__name__)

class ViessmannProtocol(asyncio.Protocol):
    _ACK = 0x06
    _START_BYTE = 0x41
    _PERIODIC_WORD = 0x05
    _END_COMMUNICATION = b"\x04"
    _PING = b"\x16\x00\x00"
    _BAUD_RATE = 4800

    def __init__(self, url):
        super().__init__()
        self._url = urlparse(url)
        self._transport = None
        self._loop = None
        self._running = False
        self._connected = False
        self._buf = b''
        self._lock = None
        self._viessmann_lock = None
        self._read_lock = None
        self._ack_event = asyncio.Event()
        self._periodic_event = asyncio.Event()
        self._sent_pkt = None
        self._recv_future = None

    def data_received(self, data: bytes):
        self._transport.pause_reading()
        self._buf += data
        while len(self._buf) > 0:
            if self._buf[0] == self._ACK:
                self._buf = self._buf[1:]
                self._ack_event.set()
            elif self._buf[0] == self._PERIODIC_WORD:
                self._buf = self._buf[1:]
                if self._running:
                    if not self._viessmann_lock.locked():
                        if self._connected:
                            logger.debug("Viessmann disconnected")
                            self._connected = False
                    else:
                        self._periodic_event.set()
            elif self._buf[0] == self._START_BYTE:
                if len(self._buf) < 3:
                    break

                length = self._buf[1]
                if len(self._buf) < length+3:
                    break

                msg_bytes, self._buf = self._buf[:length+3], self._buf[length+3:]

                try:
                    pkt = VS2Header(msg_bytes)
                except:
                    pkt = Raw(msg_bytes)

                if not self._recv_future or \
                   self._recv_future.done() or \
                   self._recv_future.cancelled():
                    continue

                if pkt.answers(self._sent_pkt):
                    self._recv_future.set_result(pkt)
                else:
                    logger.error("%s does not answer %s", pkt.show(dump=True), self._sent_pkt.show(dump=True))
                    self._recv_future.cancel()
            else:
                logger.error("Unknown byte: %02x" % (self._buf[0]))
                self._buf = self._buf[1:]

        self._transport.resume_reading()

    async def _send_ack(self, data, timeout=3):
        self._transport.write(data)
        await asyncio.wait_for(self._ack_event.wait(), timeout)
        self._ack_event.clear()

    async def send(self, pkt, timeout=3):
        async with self._read_lock:
            if not self._connected:
                await self._reconnect_viessmann()
            await self._send_ack(bytes(pkt), timeout)

    async def send_recv(self, pkt, timeout=3):
        async with self._read_lock:
            self._sent_pkt = pkt
            self._recv_future = self._loop.create_future()
            if not self._connected:
                await self._reconnect_viessmann()
            await self._send_ack(bytes(pkt), timeout)
            return await asyncio.wait_for(self._recv_future, timeout)

    async def readdata(self, address, length):
        request = VS2Header() / VS2Data(type="request", command="readdata", address=address, data_len=length)
        response = await self.send_recv(request)
        if response.type == 0x01: # response
            return response.data
        else:
            raise Exception("error reading data: %s" % (response.show(dump=True)))

    async def writedata(self, address, data):
        request = VS2Header() / VS2Data(type="request", command="writedata", address=address, data_len=len(data), data=data)
        response = await self.send_recv(request)
        if response.type != 0x01: # response
            raise Exception("error writing data: %s" % (response.show(dump=True)))

    async def _reconnect_viessmann(self):
        logger.debug("Viessmann reconnecting...")
        self._periodic_event.clear()
        async with self._viessmann_lock:
            self._transport.write(self._END_COMMUNICATION)
            await asyncio.wait_for(self._periodic_event.wait(), 4)
            await self._send_ack(self._PING, timeout=2)
            self._connected = True
            logger.debug("viessmann connected")

    def connection_lost(self, exc: Exception):
        logger.debug('port closed')
        if self._running and not self._lock.locked():
            asyncio.ensure_future(self._reconnect())

    async def _create_connection(self):
        if self._url.scheme == 'socket':
            kwargs = {
                'host': self._url.hostname,
                'port': self._url.port,
            }
            coro = self._loop.create_connection(lambda: self, **kwargs)
        else:
            kwargs = {
                'url': self._url.geturl(),
                'baudrate': self._BAUD_RATE,
                'parity': serial.PARITY_EVEN,
                'stopbits': serial.STOPBITS_TWO
            }
            coro = create_serial_connection(self._loop, lambda: self, **kwargs)
        return await coro

    async def _reconnect(self, delay: int = 10):
        async with self._lock:
            await self._disconnect()
            await asyncio.sleep(delay)
            try:
                async with timeout(5):
                    self._transport, _ = await self._create_connection()
            except (BrokenPipeError, ConnectionRefusedError,
                    serial.SerialException, asyncio.TimeoutError) as exc:
                logger.warning(exc)
                asyncio.ensure_future(self._reconnect())
            else:
                logger.info('Connected to %s', self._url.geturl())

    async def connect(self, loop):
        if self._running:
            return

        self._loop = loop
        self._lock = asyncio.Lock()
        self._viessmann_lock = asyncio.Lock()
        self._read_lock = asyncio.Lock()
        self._running = True
        await self._reconnect(delay=0)

    async def _disconnect(self):
        if self._transport:
            self._transport.abort()
            self._transport = None
