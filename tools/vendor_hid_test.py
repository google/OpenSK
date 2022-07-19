"""These tests verify the functionality of the VendorHID interface."""
from typing import Dict, Iterable
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
_BROADCAST_CID = bytes([0xFF, 0xFF, 0xFF, 0xFF])


def sleep():
  # TODO(liamjm): remove this sleep once it is not necessary.
  time.sleep(.01)
  pass


def ping_data_size(packets):
  return 57 + 59 * (packets - 1)


def get_byte():
  """Return a unique byte value per request."""
  get_byte.byte_val += 1
  return get_byte.byte_val


get_byte.byte_val = 0x10


class HidDevice(object):
  """Class that helps interact with HID devices."""

  def __init__(self, device):
    self.device = device
    self.dev = None
    self.cid = None
    self.rx_packets = []
    self.create_and_init()

  def __del__(self):
    if self.dev:
      self.dev.close()

  def reset(self) -> None:
    self.rx_packets = []

  def create_and_init(self) -> None:
    self.dev = hid.Device(path=self.device['path'])
    # Nonce is all zeros, because we don't care.
    init_packet = [0] + list(_BROADCAST_CID) + [0x86, 0x00, 0x08] + [0x00] * 57
    assert len(init_packet) == _SEND_DATA_SIZE, (
        f'Expected packet to be {_SEND_DATA_SIZE} but was {len(init_packet)}')
    self.dev.write(bytes(init_packet))
    self.cid = self.dev.read(_PACKET_SIZE, 2000)[15:19]
    sleep()

  def ping_init(self, packets=1, byte=0x88) -> int:
    size = ping_data_size(packets)
    ping_packet = [0] + list(self.cid) + [0x81, size // 256, size % 256
                                         ] + [byte] * 57
    assert len(ping_packet) == _SEND_DATA_SIZE, (
        f'Expected packet to be {_SEND_DATA_SIZE} but was {len(ping_packet)}')

    r = self.dev.write(bytes(ping_packet))
    sleep()
    return r

  def ping_continue(self, num, byte=0x88) -> int:
    continue_packet = [0] + list(self.cid) + [num] + [byte] * 59
    assert len(continue_packet) == _SEND_DATA_SIZE, (
        f'Expected packet to be {_SEND_DATA_SIZE} '
        'but was {len(continue_packet)}')
    r = self.dev.write(bytes(continue_packet))
    sleep()
    return r

  def read_and_print(self) -> int:
    d = self.dev.read(_PACKET_SIZE, 2000)
    self.rx_packets.append(d)
    sleep()
    return len(d)

  def get_received_data(self) -> bytes:
    """This combines the data from the received packets, to match the ping
packets sent."""
    d = b''
    d += self.rx_packets.pop(0)[7:]
    for p in self.rx_packets:
      d += p[5:]
    return d


def get_devices(usage_page) -> Iterable[Dict]:
  for device in hid.enumerate(_OPENSK_VID, _OPENSK_PID):
    if device['usage_page'] == usage_page:
      yield device


class HidInterfaces(unittest.TestCase):
  """Tests for the Vendor and FIDO HID interfaces."""

  @classmethod
  def setUpClass(cls):
    cls.fido_hid = cls.get_device(_FIDO_USAGE_PAGE)
    cls.vendor_hid = cls.get_device(_VENDOR_USAGE_PAGE)

  @classmethod
  def get_device(cls, usage_page) -> HidDevice:
    devices = list(get_devices(usage_page))
    if len(devices) != 1:
      raise Exception(f'Found {len(devices)} devices')
    return HidDevice(devices[0])

  def setUp(self) -> None:
    super().setUp()
    # Ensure the rx_packets are empty
    self.fido_hid.reset()
    self.vendor_hid.reset()

  def assertReceivedDataMatches(self, device: HidDevice, byte):
    expected = bytes([byte] * ping_data_size(_PACKETS))
    self.assertEqual(len(device.rx_packets), _PACKETS)
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
    self.assertNotEqual(self.vendor_hid.cid, _BROADCAST_CID)

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

  def _test_send_and_receive(self, a: HidDevice):
    byte_a = get_byte()
    r = a.ping_init(packets=_PACKETS, byte=byte_a)
    self.assertEqual(r, _SEND_DATA_SIZE)
    for i in range(_PACKETS - 1):
      r = a.ping_continue(i, byte=byte_a)
      self.assertEqual(r, _SEND_DATA_SIZE)
    for i in range(_PACKETS):
      r = a.read_and_print()
      self.assertEqual(r, _PACKET_SIZE)
    self.assertReceivedDataMatches(a, byte_a)

  def test_04_send_and_receive_fido(self):
    self._test_send_and_receive(self.fido_hid)

  def test_05_send_and_receive_vendor(self):
    self._test_send_and_receive(self.vendor_hid)

  def _test_interleaved_send_and_receive(self, a: HidDevice, b: HidDevice):
    byte_a = get_byte()
    byte_b = get_byte()
    r = a.ping_init(packets=_PACKETS, byte=byte_a)
    self.assertEqual(r, _SEND_DATA_SIZE)
    r = b.ping_init(packets=_PACKETS, byte=byte_b)
    self.assertEqual(r, _SEND_DATA_SIZE)
    for i in range(_PACKETS - 1):
      r = a.ping_continue(i, byte=byte_a)
      self.assertEqual(r, _SEND_DATA_SIZE)
      r = b.ping_continue(i, byte=byte_b)
      self.assertEqual(r, _SEND_DATA_SIZE)
    for i in range(_PACKETS):
      r = a.read_and_print()
      self.assertEqual(r, _PACKET_SIZE)
      r = b.read_and_print()
      self.assertEqual(r, _PACKET_SIZE)
    self.assertReceivedDataMatches(a, byte_a)
    self.assertReceivedDataMatches(b, byte_b)

  def test_06_interleaved_send_and_receive_fido_first(self):
    self._test_interleaved_send_and_receive(self.fido_hid, self.vendor_hid)

  def test_07_interleaved_send_and_receive_vendor_first(self):
    self._test_interleaved_send_and_receive(self.vendor_hid, self.fido_hid)

  def _test_interleaved_send_and_batch_receive(self, a: HidDevice,
                                               b: HidDevice):
    byte_a = get_byte()
    byte_b = get_byte()
    r = a.ping_init(packets=_PACKETS, byte=byte_a)
    self.assertEqual(r, _SEND_DATA_SIZE)
    r = b.ping_init(packets=_PACKETS, byte=byte_b)
    self.assertEqual(r, _SEND_DATA_SIZE)
    for i in range(_PACKETS - 1):
      r = a.ping_continue(i, byte=byte_a)
      self.assertEqual(r, _SEND_DATA_SIZE)
      r = b.ping_continue(i, byte=byte_b)
      self.assertEqual(r, _SEND_DATA_SIZE)
    for i in range(_PACKETS):
      r = a.read_and_print()
      self.assertEqual(r, _PACKET_SIZE)
    for i in range(_PACKETS):
      r = b.read_and_print()
      self.assertEqual(r, _PACKET_SIZE)
    self.assertReceivedDataMatches(a, byte_a)
    self.assertReceivedDataMatches(b, byte_b)

  def test_08_interleaved_send_and_batch_receive_fido_first(self):
    self._test_interleaved_send_and_batch_receive(self.fido_hid,
                                                  self.vendor_hid)

  def test_09_interleaved_send_and_batch_receive_vendor_first(self):
    self._test_interleaved_send_and_batch_receive(self.vendor_hid,
                                                  self.fido_hid)

  def _test_batch_send_and_interleaved_receive(self, a: HidDevice,
                                               b: HidDevice):
    byte_a = get_byte()
    byte_b = get_byte()
    r = a.ping_init(packets=_PACKETS, byte=byte_a)
    self.assertEqual(r, _SEND_DATA_SIZE)
    for i in range(_PACKETS - 1):
      r = a.ping_continue(i, byte=byte_a)
      self.assertEqual(r, _SEND_DATA_SIZE)
    r = b.ping_init(packets=_PACKETS, byte=byte_b)
    for i in range(_PACKETS - 1):
      r = b.ping_continue(i, byte=byte_b)
      self.assertEqual(r, _SEND_DATA_SIZE)
    for i in range(_PACKETS):
      r = a.read_and_print()
      self.assertEqual(r, _PACKET_SIZE)
      r = b.read_and_print()
      self.assertEqual(r, _PACKET_SIZE)
    self.assertReceivedDataMatches(a, byte_a)
    self.assertReceivedDataMatches(b, byte_b)

  def test_10_batch_send_and_interleaved_receive_fido_first(self):
    self._test_batch_send_and_interleaved_receive(self.fido_hid,
                                                  self.vendor_hid)

  def test_11_batch_send_and_interleaved_receive_vendor_first(self):
    self._test_batch_send_and_interleaved_receive(self.vendor_hid,
                                                  self.fido_hid)


if __name__ == '__main__':
  unittest.main()
