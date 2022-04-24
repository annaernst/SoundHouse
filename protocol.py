from collections import namedtuple
import struct
import hashlib

Packet = namedtuple('Packet','magic sequence_number typeb option whoami peer hash_0 hash_1 hash_2 hash_3 replyport data_length data')

def hash_data(data):
  hasher = hashlib.sha256()
  hasher.update(data)
  return int.from_bytes(hasher.digest(), 'little', signed=False)

def make_packet(
  sequence_number: int,
  typeb: int,
  cont: bool,
  multicast: bool,
  data: bytearray,
  whoami: int,
  peer: int,
  replyport: int,
  hash: int
) -> bytearray:
  typeb = typeb & 65535
  option_byte = cont & 0x80 + multicast & 0x40
  if len(data) > 1024:
    raise Exception("This layer can't handle packet splitting.")
  datalength = len(data)

  hash0 = hash & 0xFFFFFFFF
  hash1 = (hash >> 32) & 0xFFFFFFFF
  hash2 = (hash >> 64) & 0xFFFFFFFF
  hash3 = (hash >> 96) & 0xFFFFFFFF
  
  return struct.pack('<IIHB4xQQ4IHH1024s',
                int.from_bytes(bytes('𝅘𝅥𝅮','utf-8'), 'little', signed=False),
                sequence_number,
                typeb,
                option_byte,
                whoami,
                peer,
                hash0,
                hash1,
                hash2,
                hash3,
                replyport,
                datalength,
                data)
  pass

def prepare_packet(sequence_number: int,
  typeb: int,
  cont: bool,
  multicast: bool,
  data: bytearray,
  whoami: int,
  peer: int,
  replyport: int):
  hash = hash_data(data)
  return make_packet(sequence_number, typeb, cont, multicast, data, whoami, peer, replyport, hash)


def unpack_packet(packet: bytes):
  if(len(packet) < 41):
    return False
  return Packet._make(struct.unpack('<IIHB4xQQ4IHH1024s', packet))

