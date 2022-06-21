"""These tests verify the functionality of the VendorHID interface."""
import hid
import time
import unittest

_OPENSK_VID = 0x1915
_OPENSK_PID = 0x521F
_FIDO_USAGE_PAGE = 0xF1D0
_VENDOR_USAGE_PAGE = 0xFF00
_PACKETS = 4
_PACKET_SIZE = 64
_SEND_DATA_SIZE = _PACKET_SIZE + 1
_DEFAULT_CID = bytes([0xFF, 0xFF, 0xFF, 0xFF])

def sleep():
    time.sleep(.01)

def ping_data_size(packets):
  return 57 + 59 * (packets - 1)

class HidDevice(object):
    def __init__(self, device):
        self.device = device
        self.dev = None
        self.cid = None
        self.rx_packets = []
        self.create_and_init()

    def __del__(self):
        if self.dev:
          self.dev.close()


    def create_and_init(self) -> None:
        self.dev = hid.Device(path=self.device['path'])
        # Nonce is all zeros, because we don't care.
        init_packet = [0] + list(_DEFAULT_CID) + [0x86, 0x00, 0x08] + [0x00] * 57
        if len(init_packet) != _SEND_DATA_SIZE:
          raise Exception("Expected packet to be %d but was %d" % (_SEND_DATA_SIZE, len(init_packet)))
        self.dev.write(bytes(init_packet))
        self.cid = self.dev.read(_PACKET_SIZE, 2000)[15:19]
        sleep()

    def ping_init(self, packets=1, byte=0x88) -> int:
        size = ping_data_size(packets)
        ping_packet = [0] + list(self.cid) + [0x81, size // 256, size % 256] + [byte] * 57
        if len(ping_packet) != _SEND_DATA_SIZE:
          raise Exception("Expected packet to be %d but was %d" % (_PACKET_SIZE, len(ping_packet)))
        r = self.dev.write(bytes(ping_packet))
        sleep()
        return r


    def ping_continue(self, num, byte=0x88) -> int:
        continue_packet = [0] + list(self.cid) + [num] + [byte] * 59
        if len(continue_packet) != _SEND_DATA_SIZE:
          raise Exception("Expected packet to be %d but was %d" % (_PACKET_SIZE, len(continue_packet)))
        r = self.dev.write(bytes(continue_packet))
        sleep()
        return r

    def read_and_print(self) -> int:
        d = self.dev.read(_PACKET_SIZE, 2000)
        self.rx_packets.append(d)
        sleep()
        return len(d)

    def get_received_data(self):
      """This combines the data from the received packets, to match the ping
      packets sent."""
      d = b""
      if len(self.rx_packets) < _PACKETS:
        raise Exception("Insufficent packets received - want %d, got %d" % (_PACKETS, len(self.rx_packets)))
      d += self.rx_packets[-_PACKETS][7:]
      for p in self.rx_packets[-_PACKETS+1:]:
        d += p[5:]
      return d


def get_devices(usage_page):
    for device in hid.enumerate(_OPENSK_VID, _OPENSK_PID):
        if device['usage_page'] == usage_page:
            yield device


class VendorHid(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fido_hid = cls.get_device(_FIDO_USAGE_PAGE)
        cls.vendor_hid = cls.get_device(_VENDOR_USAGE_PAGE)

    @classmethod
    def get_device(cls, usage_page):
      devices = list(get_devices(usage_page))
      if len(devices) != 1:
        raise Exception("Found %d devices" % len(devices))
      return HidDevice(devices[0])

    def assertReceivedDataMatches(self, device: HidDevice, byte):
        expected = bytes([byte]*ping_data_size(_PACKETS))
        self.assertEqual(device.get_received_data(), expected)

    def test_00_init(self):
        self.assertNotEqual(self.vendor_hid, None)
        self.assertNotEqual(self.vendor_hid.device, None)
        self.assertNotEqual(self.vendor_hid.dev, None)
        self.assertNotEqual(self.vendor_hid.cid, None)

        self.assertNotEqual(self.fido_hid, None)
        self.assertNotEqual(self.fido_hid.device, None)
        self.assertNotEqual(self.fido_hid.dev, None)
        self.assertNotEqual(self.fido_hid.cid, None)

    def test_01_cid(self):
        self.assertNotEqual(self.vendor_hid.cid, _DEFAULT_CID)

    def _test_ping(self, dev: HidDevice, byte):
        r = dev.ping_init(_PACKETS, byte)
        self.assertEqual(r, _SEND_DATA_SIZE)
        for i in range(_PACKETS - 1):
            r = dev.ping_continue(i, byte)
            self.assertEqual(r, _SEND_DATA_SIZE)
        for _ in range(_PACKETS):
            r = dev.read_and_print()
            self.assertEqual(r, _PACKET_SIZE)
        self.assertReceivedDataMatches(dev, byte)

    def test_02_fido_ping(self):
      self._test_ping(self.fido_hid, byte=0x11)

    def test_03_vendor_ping(self):
      self._test_ping(self.vendor_hid, byte=0x22)

    def test_04_interleaved_send_and_receive(self):
        r = self.fido_hid.ping_init(packets=_PACKETS, byte=0x33)
        self.assertEqual(r, _SEND_DATA_SIZE)
        r = self.vendor_hid.ping_init(packets=_PACKETS, byte=0x44)
        self.assertEqual(r, _SEND_DATA_SIZE)
        for i in range(_PACKETS - 1):
            r = self.fido_hid.ping_continue(i, byte=0x33)
            self.assertEqual(r, _SEND_DATA_SIZE)
            r = self.vendor_hid.ping_continue(i, byte=0x44)
            self.assertEqual(r, _SEND_DATA_SIZE)
        for i in range(_PACKETS):
            r = self.fido_hid.read_and_print()
            self.assertEqual(r, _PACKET_SIZE)
            r = self.vendor_hid.read_and_print()
            self.assertEqual(r, _PACKET_SIZE)
        self.assertReceivedDataMatches(self.fido_hid, 0x33)
        self.assertReceivedDataMatches(self.vendor_hid, 0x44)

    def test_05_interleaved_send_and_batch_receive(self):
        r = self.fido_hid.ping_init(packets=_PACKETS, byte=0x55)
        self.assertEqual(r, _SEND_DATA_SIZE)
        r = self.vendor_hid.ping_init(packets=_PACKETS, byte=0x66)
        self.assertEqual(r, _SEND_DATA_SIZE)
        for i in range(_PACKETS - 1):
            r = self.fido_hid.ping_continue(i, byte=0x55)
            self.assertEqual(r, _SEND_DATA_SIZE)
            r = self.vendor_hid.ping_continue(i, byte=0x66)
            self.assertEqual(r, _SEND_DATA_SIZE)
        for i in range(_PACKETS):
            r = self.fido_hid.read_and_print()
            self.assertEqual(r, _PACKET_SIZE)
        for i in range(_PACKETS):
            r = self.vendor_hid.read_and_print()
            self.assertEqual(r, _PACKET_SIZE)
        self.assertReceivedDataMatches(self.fido_hid, 0x55)
        self.assertReceivedDataMatches(self.vendor_hid, 0x66)

    def test_06_batch_send_and_interleaved_receive(self):
        r = self.fido_hid.ping_init(packets=_PACKETS, byte=0x77)
        self.assertEqual(r, _SEND_DATA_SIZE)
        for i in range(_PACKETS - 1):
            r = self.fido_hid.ping_continue(i, byte=0x77)
            self.assertEqual(r, _SEND_DATA_SIZE)
        r = self.vendor_hid.ping_init(packets=_PACKETS, byte=0x88)
        for i in range(_PACKETS - 1):
            r = self.vendor_hid.ping_continue(i, byte=0x88)
            self.assertEqual(r, _SEND_DATA_SIZE)
        for i in range(_PACKETS):
            r = self.fido_hid.read_and_print()
            self.assertEqual(r, _PACKET_SIZE)
            r = self.vendor_hid.read_and_print()
            self.assertEqual(r, _PACKET_SIZE)
        self.assertReceivedDataMatches(self.fido_hid, 0x77)
        self.assertReceivedDataMatches(self.vendor_hid, 0x88)

if __name__ == '__main__':
    unittest.main()
