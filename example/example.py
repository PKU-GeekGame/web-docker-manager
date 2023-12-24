import os
import json
from shutil import copyfile
from flask import Flask,request,render_template,url_for,send_from_directory,make_response
from flask import jsonify
from hashlib import md5

app = Flask("example")

f=open("/flag")
gflag=f.read()
f.close()

@app.route('/',methods=["GET"])
def index():
    response = make_response(render_template('index.html'))
    return response

@app.route('/test',methods=["POST"])
def testpost():
    namev=request.form['name']
    return "Hi %s: Your flag is %s"%(namev,gflag)


app.run(host="0.0.0.0",port=8080,debug=True,threaded=True)
