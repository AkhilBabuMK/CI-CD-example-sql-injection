import base64

from flask import Flask, send_from_directory, request

app = Flask(__name__)

@app.route('/')
def hello():
    return send_from_directory('static', 'index.html')

def get_important_json(inp):
    b = base64.b64encode(inp.encode("utf8")).decode("utf8")

    return {
        "bla": b,
    }

@app.route('/json')
def tatata():
    return get_important_json(request.args.get('a'))


if __name__ == "__main__":
    app.run()
