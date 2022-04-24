CREATE TABLE IF NOT EXISTS connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  passphrase text,
  bridge_server text
);

CREATE TABLE IF NOT EXISTS songs (
  id INTEGER PRIMARY KEY,
  bpm INTEGER,
  songname text
);

CREATE TABLE IF NOT EXISTS tracks (
  trackid INTEGER PRIMARY KEY,
  songid INTEGER,
  trackname text,
  timestmp INTEGER,
  FOREIGN KEY(songid) REFERENCES songs(id)
);

CREATE TABLE IF NOT EXISTS pieces (
  id BLOB,
  trackid INTEGER,
  present BOOLEAN,
  sequence_number INTEGER,
  data BLOB,

  FOREIGN KEY(trackid) REFERENCES tracks(trackid)
);
