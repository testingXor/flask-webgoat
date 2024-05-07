import pickle
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)


@bp.route("/message", methods=["POST"])
def log_entry():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})
    access_level = user_info[2]
    if access_level > 2:
        return jsonify({"error": "access level < 2 is required for this action"})
    filename_param = request.form.get("filename")
    if filename_param is None:
        return jsonify({"error": "filename parameter is required"})
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"})

    user_id = user_info[0]
    user_dir = "data/" + str(user_id)
    user_dir_path = Path(user_dir)
    if not user_dir_path.exists():
        user_dir_path.mkdir()

    filename = filename_param + ".txt"
    path = Path(user_dir + "/" + filename)
    # vulnerability: Directory Traversal
    '''
    ***************** OpenRefactory Warning *****************
    Possible Path manipulation attack!
    Path:
    	File: actions.py, Line: 19
    		filename_param = request.form.get("filename")
    		Variable filename_param is assigned a tainted value from an external source.
    	File: actions.py, Line: 32
    		filename = filename_param + ".txt"
    		Variable filename is assigned a tainted value.
    	File: actions.py, Line: 33
    		path = Path(user_dir + "/" + filename)
    		Variable path is assigned a tainted value which is passed through a method invocation.
    	File: actions.py, Line: 35
    		with path.open("w", encoding="utf-8") as open_file:
    		        open_file.write(text_param)
    		Tainted information is used in a sink.
    '''
    with path.open("w", encoding="utf-8") as open_file:
        open_file.write(text_param)
    return jsonify({"success": True})


@bp.route("/grep_processes")
def grep_processes():
    name = request.args.get("name")
    # vulnerability: Remote Code Execution
    '''
    ***************** OpenRefactory Warning *****************
    Possible OS command injection!
    Path:
    	File: actions.py, Line: 42
    		name = request.args.get("name")
    		Variable name is assigned a tainted value from an external source.
    	File: actions.py, Line: 44
    		res = subprocess.run(
    		        ["ps aux | grep " + name + " | awk '{print $11}'"],
    		        shell=True,
    		        capture_output=True,
    		    )
    		Tainted information is used in a sink.
    '''
    res = subprocess.run(
        ["ps aux | grep " + name + " | awk '{print $11}'"],
        shell=True,
        capture_output=True,
    )
    if res.stdout is None:
        return jsonify({"error": "no stdout returned"})
    out = res.stdout.decode("utf-8")
    names = out.split("\n")
    return jsonify({"success": True, "names": names})


@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
