import os
import sqlite3
from pathlib import Path

from flask import Flask, g

DB_FILENAME = "database.db"


def query_db(query, args=(), one=False, commit=False):
    with sqlite3.connect(DB_FILENAME) as conn:
        # vulnerability: Sensitive Data Exposure
        conn.set_trace_callback(print)
        '''
        ***************** OpenRefactory Warning *****************
        Possible SQL injection!
        Path:
        	File: auth.py, Line: 9
        		username = request.form.get("username")
        		Variable username is assigned a tainted value from an external source.
        	File: auth.py, Line: 10
        		password = request.form.get("password")
        		Variable password is assigned a tainted value from an external source.
        	File: auth.py, Line: 18
        		query = (
        		        "SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
        		        % (username, password)
        		    )
        		Variable query is assigned a tainted value.
        	File: auth.py, Line: 22
        		result = query_db(query, [], True)
        		Tainted information is passed through a method call via query to the formal parameter query of the method.
        	File: __init__.py, Line: 14
        		cur = conn.cursor().execute(query, args)
        		Tainted information is used in a sink.
        '''
        cur = conn.cursor().execute(query, args)
        if commit:
            conn.commit()
        return cur.fetchone() if one else cur.fetchall()


def create_app():
    app = Flask(__name__)
    app.secret_key = "aeZ1iwoh2ree2mo0Eereireong4baitixaixu5Ee"

    db_path = Path(DB_FILENAME)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(DB_FILENAME)
    create_table_query = """CREATE TABLE IF NOT EXISTS user
    (id INTEGER PRIMARY KEY, username TEXT, password TEXT, access_level INTEGER)"""
    conn.execute(create_table_query)

    insert_admin_query = """INSERT INTO user (id, username, password, access_level)
    VALUES (1, 'admin', 'admin', 0)"""
    conn.execute(insert_admin_query)
    conn.commit()
    conn.close()

    with app.app_context():
        from . import actions
        from . import auth
        from . import status
        from . import ui
        from . import users

        app.register_blueprint(actions.bp)
        app.register_blueprint(auth.bp)
        app.register_blueprint(status.bp)
        app.register_blueprint(ui.bp)
        app.register_blueprint(users.bp)
        return app
