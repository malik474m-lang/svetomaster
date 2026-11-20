// Known uDMX-class sticks: V-USB devices with no endpoints that take DMX frames
// over vendor control transfers. One table shared by the transport and the
// diagnostics so a new model can never be half-supported (visible in the scan
// but invisible to hotplug/reports, or the other way round).
//
// `session` marks clones that require a vendor handshake before they accept
// DMX. Their DMX request number is masked with a per-session random byte, so
// the raw bRequest differs on every connection (see UdmxTransport._openSession).
const UDMX_MODELS = [
  {
    vid: 0x16C0,
    pid: 0x05DC,
    name: 'uDMX (USB)',
    idPrefix: 'udmx',
    session: false,
  },
  {
    // CYL-6602 and friends, sold as "USBDMX512". Same ATmega8 + 12 MHz design as
    // the original uDMX, different vendor id and a session handshake on top.
    vid: 0x2008,
    pid: 0x1066,
    name: 'USBDMX512 (Sun-light)',
    idPrefix: 'usbdmx512',
    session: true,
  },
];

// Session handshake constants, taken from the vendor's own USB-DMX.dll:
//   IN  0xC0 / 0x11 / wValue 0x3322 / wIndex 0x0044 | (N << 8), 4 bytes
//   the device answers its signature XOR N; the library only checks the last
//   byte, which must equal N ^ 0x8A.
const SESSION_REQUEST = 0x11;
const SESSION_VALUE = 0x3322;
const SESSION_INDEX_BASE = 0x0044;
const SESSION_ANSWER_MASK = 0x8A;

function modelOf(device) {
  const descriptor = device && device.deviceDescriptor;
  if (!descriptor) return null;
  return UDMX_MODELS.find(m =>
    m.vid === descriptor.idVendor && m.pid === descriptor.idProduct) || null;
}

function modelByIds(vid, pid) {
  return UDMX_MODELS.find(m => m.vid === vid && m.pid === pid) || null;
}

module.exports = {
  UDMX_MODELS,
  SESSION_REQUEST,
  SESSION_VALUE,
  SESSION_INDEX_BASE,
  SESSION_ANSWER_MASK,
  modelOf,
  modelByIds,
};
