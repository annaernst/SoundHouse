from collections import namedtuple
import sqlite3
from time import time

from flask import request
from numpy import byte
import protocol
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import hashlib
import struct
import requests

import sys

con: sqlite3.Connection = None

output_queue = list()

candidate_tracks = list()

configurations = {
  'listen_port': 8000,
  'testing_mode': 0
}

last_packet_handled = time()

def get_songs_from_db():
  cur = con.cursor()
  r = cur.execute("SELECT * FROM songs")
  return [row for row in r]

def get_tracks_for_song_from_db(songid):
  cur = con.cursor()
  r = cur.execute("SELECT * FROM tracks WHERE songid = ?", (songid,))
  return [row for row in r]

def get_piece_info_for_song_from_db(trackid):
  cur = con.cursor()
  r = cur.execute("SELECT id, sequence_number FROM pieces WHERE trackid = ?", (trackid,))
  return [(int.from_bytes(row[0], 'little'), row[1]) for row in r]

def get_all_pieces_for_song_from_db(trackid):
  cur = con.cursor()
  r = cur.execute("SELECT id, sequence_number, data FROM pieces WHERE trackid = ?", (trackid,))
  return [(int.from_bytes(row[0], 'little'), row[1], row[2]) for row in r]

def add_song_from_packet(song_tuple):
  cur = con.cursor()
  cur.execute("INSERT OR IGNORE INTO songs (id, bpm, songname) VALUES (?,?,?)", song_tuple)
  print("added song")

#returns true if we have never seen this track before
def add_track_from_packet(track_tuple) -> bool:
  cur = con.cursor()
  try:
    print('ya')
    print(track_tuple)
    cur.execute("INSERT INTO tracks (trackid, songid, trackname, timestmp) VALUES (?,?,?,?)",
            track_tuple)
    print("added track")
    return True
  except:
    return False

def add_block_info_from_packet(trackid, block_info):
  cur = con.cursor()
  cur.execute("INSERT OR IGNORE INTO pieces (id, trackid, sequence_number, present) VALUES (?,?,?,?)",
              (sqlite3.Binary(int.to_bytes(block_info[1], 16, 'little')), trackid, block_info[0], False))

def set_block_db(blockid, sequence, data):
  cur = con.cursor()
  cur.execute("UPDATE pieces SET present=TRUE, data=? WHERE id=?",
              (sqlite3.Binary(data), sqlite3.Binary(int.to_bytes(blockid, 16, 'little'))))

def get_block_data(blockids):
  cur = con.cursor()
  r = cur.executemany("SELECT id, sequence_number, data FROM pieces WHERE id = ?", ((sqlite3.Binary(blockid), ) for blockid in blockids))
  return [(int.from_bytes(row[0], 'little'), row[1], row[2]) for row in r]

def max_entries_for_packet_type(pkt):
  return 1024//struct.calcsize(pkt.struct_string)

class Packet():
  seq = 0

class SongRequestPacket(Packet):
  command = 0x00
  klass = 0x01
  def serialize(self):
    return bytearray()
  @staticmethod
  def deserialize(buf):
    return SongRequestPacket()

class TrackRequestPacket(Packet):
  command = 0x01
  klass = 0x01
  id = 0
  struct_string = "<I"
  def serialize(self):
    return struct.pack(self.struct_string, self.id)
  @staticmethod
  def deserialize(buf):
    trp = TrackRequestPacket()
    print(buf)
    trp.id = struct.unpack(TrackRequestPacket.struct_string, buf)[0]
    return trp

class BlockListRequestPacket(Packet):
  command = 0x02
  klass = 0x01
  id = 0
  struct_string = "<I"
  def serialize(self):
    return struct.pack(self.struct_string, self.id)
  @staticmethod
  def deserialize(buf):
    trp = BlockListRequestPacket()
    print(buf)
    trp.id = struct.unpack(BlockListRequestPacket.struct_string, buf)[0]
    return trp

class MassBlockRequestPacket(Packet):
  command = 0x00
  klass = 0x0B
  id = 0
  struct_string = "<I"
  def serialize(self):
    return struct.pack(self.struct_string, self.id)
  @staticmethod
  def deserialize(buf):
    trp = MassBlockRequestPacket()
    print(buf)
    trp.id = struct.unpack(MassBlockRequestPacket.struct_string, buf)[0]
    return trp

class IndividualBlockRequest(Packet):
  command = 0x03
  klass = 0x0B
  struct_string = "<I4"
  blockid = 0
  def serialize(self):
    sz = struct.calcsize(self.struct_string)
    buf = bytearray(sz)
    struct.pack_into(self.struct_string, buf, 0, self.blockid & 0xFFFFFFFF, (self.blockid>>32)& 0xFFFFFFFF,(self.blockid>>64)& 0xFFFFFFFF, (self.blockid>>96)& 0xFFFFFFFF)
    return buf
  @staticmethod
  def deserialize(buf):
    l = struct.unpack(IndividualBlockRequest.struct_string, buf)
    id = l[0] | l[1] << 32 | l[2] << 64 | l[3] << 96
    blp = IndividualBlockRequest()
    blp.blockid = id
    return blp

class BlockDataPacket(Packet):
  command = 0x01
  klass = 0x0B
  data = bytes()
  struct_string = "<1024s"
  def serialize(self):
    return struct.pack(self.struct_string, self.data)
  @staticmethod
  def deserialize(buf):
    trp = BlockDataPacket()
    trp.data = struct.unpack(BlockDataPacket.struct_string, buf)[0]
    return trp


class NoBlockDataPacket(Packet):
  command = 0x02
  klass = 0x0B
  def serialize(self):
    return bytearray()
  @staticmethod
  def deserialize(buf):
    return NoBlockDataPacket()

class TrackListPacket(Packet):
  command = 0x01
  klass = 0x10
  struct_string = "<II16sI"
  track_tuples = list()
  def serialize(self):
    sz = struct.calcsize(self.struct_string)
    if sz * len(self.track_tuples) > 1024:
      raise Exception("shouldn't have gotten here")
    buf = bytearray(sz*len(self.track_tuples))
    for i in range(len(self.track_tuples)):
      t = self.track_tuples[i]
      print(t)
      struct.pack_into(self.struct_string, buf, i*sz, t[0], t[1], bytes(t[2], 'utf-8'), t[3])
    return buf
  @staticmethod
  def deserialize(buf):
    bla = [l for l in struct.iter_unpack(TrackListPacket.struct_string, buf)]
    tlp = TrackListPacket()
    tlp.track_tuples = bla
    return tlp

class SongListPacket(Packet):
  command = 0x00
  klass = 0x10
  struct_string = "<IH16s"
  # id, bpm, name
  song_pairs = list()
  
  def serialize(self):
    sz = struct.calcsize(self.struct_string)
    if sz * len(self.song_pairs) > 1024:
      raise Exception("shouldn't have gotten here")
    buf = bytearray(sz*len(self.song_pairs))
    for i in range(len(self.song_pairs)):
      s = self.song_pairs[i]
      struct.pack_into(self.struct_string, buf, i*sz, s[0], s[1], bytes(s[2], 'utf-8'))
    return buf
  @staticmethod
  def deserialize(buf): 
    sz = struct.calcsize(SongListPacket.struct_string)
    bla = list()
    for l in struct.iter_unpack(SongListPacket.struct_string, buf):
      bla.append(l)
    slp = SongListPacket()
    slp.song_pairs = bla
    return slp

class BlockListPacket(Packet):
  command = 0x02
  klass = 0x10
  struct_string = "<I4I"
  blocks = list()
  def serialize(self):
    sz = struct.calcsize(self.struct_string)
    if sz * len(self.blocks) > 1024:
      raise Exception("Shouldn't have gotten here")
    buf = bytearray(sz*len(self.blocks))
    for i in range(len(self.blocks)):
      b = self.blocks[i]
      struct.pack_into(self.struct_string, buf, i*sz, b[1], b[0] & 0xFFFFFFFF, (b[0]>>32)& 0xFFFFFFFF,(b[0]>>64)& 0xFFFFFFFF, (b[0]>>96)& 0xFFFFFFFF)
    return buf
  @staticmethod
  def deserialize(buf):
    bla = list()
    for l in struct.iter_unpack(BlockListPacket.struct_string, buf):
      bla.append((l[0], l[1] | l[2] << 32 | l[3] << 64 | l[4] << 96))
    blp = BlockListPacket()
    blp.blocks = bla
    return blp

class BaseClassHandler():
  def handle_for(self, cmd, packet, requesthandler: BaseHTTPRequestHandler):
    return False

class QueryHandler(BaseClassHandler):
  def handle_for(self, cmd, packet, requesthandler: BaseHTTPRequestHandler):
      global output_queue
      if cmd == 0x00: # get song list
        songs = get_songs_from_db()
        slp = SongListPacket()
        slp.song_pairs = songs
        output_queue.append((requesthandler.client_address[0], packet.replyport, slp))
        pass
      elif cmd == 0x01: # get list of tracks for song
        trp = TrackRequestPacket.deserialize(packet.data[:packet.data_length])
        tracks = get_tracks_for_song_from_db(trp.id)
        me = max_entries_for_packet_type(TrackListPacket)
        for i in range(len(tracks) // me +1):
          print('k')
          tlp = TrackListPacket()
          tlp.seq = i
          tlp.track_tuples = tracks[me*i: min(me*(i+1), len(tracks))]
          output_queue.append((requesthandler.client_address[0], packet.replyport, tlp))
        pass
      elif cmd == 0x02:
        brp = BlockListRequestPacket.deserialize(packet.data[:packet.data_length])
        piece_info = get_piece_info_for_song_from_db(brp.id)
        me = max_entries_for_packet_type(BlockListPacket)
        for i in range(len(piece_info) // me + 1):
          blp = BlockListPacket()
          blp.seq = brp.id
          blp.blocks = piece_info[me*i:min(me*(i+1), len(piece_info))]
          output_queue.append((requesthandler.client_address[0], packet.replyport, blp))
        pass
      else:
        return False

class QueryResponseHandler(BaseClassHandler):
  def handle_for(self, cmd, packet, requesthandler: BaseHTTPRequestHandler):
      global candidate_tracks
      if cmd == 0x00: # song list packet
        slp = SongListPacket.deserialize(packet.data[:packet.data_length])
        for song_tuple in slp.song_pairs:
          add_song_from_packet(song_tuple)
          trp = TrackRequestPacket()
          trp.id = song_tuple[0]
          output_queue.append((requesthandler.client_address[0], packet.replyport, trp))
      elif cmd == 0x01: # track list packet
        tlp = TrackListPacket.deserialize(packet.data[:packet.data_length])
        for track_tuple in tlp.track_tuples:
          if add_track_from_packet(track_tuple):
            blp = BlockListRequestPacket()
            blp.id = track_tuple[0]
            output_queue.append((requesthandler.client_address[0], packet.replyport, blp))
            # candidate_tracks.append(track_tuple[0])
      elif cmd == 0x02: # block list packet
        blp = BlockListPacket.deserialize(packet.data[:packet.data_length])
        for block_info in blp.blocks:
          add_block_info_from_packet(blp.seq, block_info)


class BlockHandler(BaseClassHandler):
  def handle_for(self, cmd, packet, requesthandler: BaseHTTPRequestHandler):
      global output_queue
      if cmd == 0x00: # mass request
        mr = MassBlockRequestPacket.deserialize(packet.data[:packet.data_length])
        blocks = get_all_pieces_for_song_from_db(mr.id) # heavy stuff
        for block in blocks:
          bdp = BlockDataPacket()
          bdp.seq = block[1]
          bdp.data = block[2]
          output_queue.append((requesthandler.client_address[0], packet.replyport, bdp)) #soz
      elif cmd == 0x01: # block data
        bd = BlockDataPacket.deserialize(packet.data[:packet.data_length])
        hash = packet.hash_0 | packet.hash_1 << 32 | packet.hash_2 << 64 | packet.hash_3 << 96
        set_block_db(hash, packet.sequence_number, bd.data)
      elif cmd == 0x02: # no block data
        nbd = NoBlockDataPacket.deserialize(packet.data[:packet.data_length])
        print('oops')
      elif cmd == 0x03: # individual block request
        ibr = IndividualBlockRequest.deserialize(packet.data[:packet.data_length])
        


class_handlers = {
  0x01: QueryHandler(),
  0x10: QueryResponseHandler(),
  0x0B: BlockHandler(),
}



def wrap_packet(packet):
  return protocol.prepare_packet(packet.seq, )

class Bla(BaseHTTPRequestHandler):
  def do_POST(self):
    global last_packet_handled
    last_packet_handled = time()
    content_len = int(self.headers.get('Content-Length'))
    if(content_len < 42):
      self.send_response(500)
      return
    for i in range(content_len//1075):
      packet = self.rfile.read(1075)
      res = protocol.unpack_packet(packet)
      if not res:
        self.send_response(500)
        return
      klass = res.typeb >> 8
      command = res.typeb & 0xFF
      if klass not in class_handlers:
        self.send_response(500)
        return
      # print(f'Request class: {klass}')
      # print(f'Request cmd: {command}')
      klass_handler = class_handlers[klass]
      klass_handler.handle_for(command, res, self)
    
    self.send_response(200)
    self.send_header('Content-Type','application/octet-stream')
    self.end_headers()
    # self.wfile.write(packet)
    pass

def run(server_class=HTTPServer, handler_class=Bla):
    global output_queue
    server_address = ('', configurations['listen_port'])
    httpd = server_class(server_address, handler_class)
    httpd.timeout = 0.1
    done = False
    s = requests.Session()
    while True:
      if time() - last_packet_handled > 3 and not done and configurations['testing_mode'] == 1:
        done = True
        mb = MassBlockRequestPacket()
        mb.id = 1168101942
        output_queue.append(("127.0.0.1", 8000, mb))
      httpd.handle_request()
      outer = bytearray()
      ip, port = None, None
      for _ in range(5000):
        con.commit()
        if len(output_queue) > 0:
          ip, port, pkt = output_queue.pop()
          outer += protocol.prepare_packet(pkt.seq, pkt.klass << 8 | pkt.command, False, False, pkt.serialize(), configurations['identity'], 0,
                          configurations['listen_port'])
        else:
          break
      try:
        if ip is not None:
          s.post(f"http://{ip}:{port}/",
                          outer)   
      except Exception as e:
            raise e
  
def ingress_new_track(songid, trackname, rawdata, timestmp) -> int:
  block_size = 1024
  blocks = list()
  blockids = list()
  indx = 0
  total = len(rawdata)
  while True:
    left = indx * block_size
    right = min(total, left+block_size)
    this_size = right-left
    if this_size <= 0:
      break
    blocks.append(bytes(rawdata[left:right]))
    indx+=1
  outer = hashlib.sha256()
  for block in blocks:
    hasher = hashlib.sha256()
    hasher.update(block)
    id = hasher.digest()
    blockids.append(id)
    outer.update(id)
  cur = con.cursor()
  trackid = int.from_bytes(outer.digest(), 'little') &0xFFFFFFFF
  cur.execute("INSERT INTO tracks (trackid, songid, trackname, timestmp) VALUES (?,?,?,?)",
                                  (trackid, songid, trackname, timestmp))
  for i in range(len(blockids)):
    cur.execute("INSERT INTO pieces (id, trackid, present, sequence_number, data) values (?,?,TRUE,?,?)",
    (sqlite3.Binary(blockids[i]), trackid, i, sqlite3.Binary(blocks[i])))
  pass

def init():
  global con
  con = sqlite3.connect(configurations['database'])#'sh.db')
  with open('schema.sql', 'r') as f:
    script = f.read()
    cur = con.cursor()
    cur.executescript(script)
  data = None
  if configurations['testing_mode'] == 0:
    con.execute("INSERT INTO songs (id, songname, bpm) values (1337, 'ChechenSong', 100)")
    con.commit()
    with open('chechen.mp3', 'rb') as f:
      data = f.read()
    ingress_new_track(1337, "woot", data, 0)
    con.commit()
    print("finished")
    print(get_tracks_for_song_from_db(1337))
  elif configurations['testing_mode'] == 1:
    output_queue.append(("127.0.0.1", 8000, SongRequestPacket()))
  run()

if __name__ == "__main__":
  configurations['listen_port'] = int(sys.argv[1])
  configurations['testing_mode'] = int(sys.argv[2])
  configurations['identity'] = int(sys.argv[3])
  configurations['database'] = sys.argv[4]
  init()