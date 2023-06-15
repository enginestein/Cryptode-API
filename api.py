from flask import Flask
from src.cryptode import *

app = Flask("Cryptode")

for name, func in globals().items():
    if callable(func) and name != 'app':
        app.add_url_rule('/' + name, view_func=func)

if __name__ == '__main__':
    app.run()