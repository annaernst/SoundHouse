from flask import Flask, render_template
app = Flask(__name__,
            static_url_path='',
            static_folder='/')

@app.route("/")
@app.route("/index")
def index():
    song1 = {'id': '1234', 'title': 'Song One', 'duration': '3.14'}
    return render_template('index.html', song1=song1)

@app.route("/join")
def join():
    return render_template('join.html')

@app.route("/song/<song_id>/")
def song(song_id):
    song1 = {'id': '1234', 'title': 'Song One'}
    track1 = {'id': '9', 'title': 'Guitar 1'}
    return render_template('song.html', song_id=song_id, song1=song1, track1=track1)

if __name__ == "__main__":
    app.run()