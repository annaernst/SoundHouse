from flask import Flask, render_template, request, Response
app = Flask(__name__,
            static_url_path='',
            static_folder='/')

@app.route("/", methods=["POST"])
def handle_upload():
    with open('yeet.webm', 'wb') as f:
        f.write(request.get_data())
    return Response("nice")
@app.route("/title", methods=["POST"])
def handle_title():
    with open('track1.txt', 'r+') as f:
        data = f.read()
        print(data)
        print(len(data))
        f.write(data[len(data)-2]+','+request.get_data(as_text=True)+']')
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
    with open('track1.txt', 'r') as f:
        track1=eval(f.read())
        #track1 = [{'id': '9', 'title': 'Guitar 1', 'file': 'chechen.mp3'}]
        song1 = {'id': '1234', 'title': 'Song One', 'tracks': track1}
        return render_template('song.html', song_id=song_id, song1=song1)

if __name__ == "__main__":
    app.run()
