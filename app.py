import os
from flask import Flask
from blueprints.auth import auth_bp
from blueprints.users import users_bp


app = Flask(__name__)
app.secret_key = os.urandom(24)
app.debug = True

app.register_blueprint(auth_bp)
app.register_blueprint(users_bp)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
