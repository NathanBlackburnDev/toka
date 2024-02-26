from flask import Flask
from datetime import timedelta

# Configure Flask app
app = Flask(__name__)
app.secret_key = 'wahdiuoawhfgoawtgp094214e'
app.permanent_session_lifetime = timedelta(days=1)
import routes

# Only run app if being directly run
if __name__ == '__main__':
    app.run(debug=True)