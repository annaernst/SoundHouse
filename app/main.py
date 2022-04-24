from flask import Flask, render_template, request, Response
app = Flask(__name__,
            static_url_path='',
            static_folder='/')

@app.route("/", methods=["POST"])
def handle_upload():
    with open('yeet.webm', 'wb') as f:
        f.write(request.get_data())
    return Response("nice")
@app.route("/", methods=["GET"])
@app.route("/index")
def index():
    song1 = {'id': '1234', 'title': 'Song One', 'duration': '3.14'}
    return render_template('index.html', song1=song1)

@app.route("/join")
def join():
    return render_template('join.html')

@app.route("/song/<song_id>/")
def song(song_id):
    track1 = [{'id': '9', 'title': 'Guitar 1', 'file': 'chechen.mp3'}]
    song1 = {'id': '1234', 'title': 'Song One', 'tracks': track1}
    return render_template('song.html', song_id=song_id, song1=song1)

@app.route("/newsong")
def newsong():
    return render_template('newsong.html')

if __name__ == "__main__":
    app.run()
