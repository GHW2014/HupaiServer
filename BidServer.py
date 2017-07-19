from sqlite3 import dbapi2 as sqlite3
from flask import Flask, request, g, redirect, url_for, abort, render_template, flash, current_app
from werkzeug.utils import secure_filename
import os


from Crypto import Random
from Crypto.Hash import MD5
import base64
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA

from datetime import datetime
from calendar import timegm

import logging
from logging import Formatter, FileHandler



app = Flask(__name__)

app.config.update(
    UPLOAD_FOLDER = 'uploads',
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024,
    DATABASE = 'BidServer.db3',
    ALLOWED_EXTENSIONS = set(['zip']),
)


# For a given file, return whether it's an allowed type or not
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']
           

def generate_sn(msg):
    
    fmt = '%Y-%m-%d %H:%M:%S %z'

    tm = '2017-09-01 00:00:00 +0000'
    # 伪随机数生成器
    random_generator = Random.new().read
    # rsa算法生成实例
    rsa = RSA.generate(1024, random_generator)
    text=""
    with open('hupaibid.pem') as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        text = cipher.decrypt(base64.b64decode(msg), random_generator)
        app.logger.debug(text)

    #message=text + b'1504224000' + str(timegm(datetime.strptime(tm, fmt).utctimetuple())).encode('utf-8')

    message = "ASDSADSADSAFDSFADASFASFDAS".encode('utf-8')
    app.logger.debug(message)

    with open('hupaibid.pem') as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        signer = Signature_pkcs1_v1_5.new(rsakey)
        digest = MD5.new()
        digest.update(message)
        sign = signer.sign(digest)
        signature = base64.b64encode(sign)
        app.logger.debug(signature)
    return signature
    
def check_register(msg):
    random_generator = Random.new().read
    rsa = RSA.generate(1024, random_generator)
    bid=''
    exp=''
    phone=''
    with open('hupaibid.pem') as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        text = cipher.decrypt(base64.b64decode(msg), random_generator)
        app.logger.debug(text)
    return text.decode("utf-8")
    

def connect_db():
    """Connects to the specific database."""
    rv = sqlite3.connect(current_app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv


def init_db():
    """Initializes the database."""
    db = get_db()
    with current_app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db




@app.route('/add', methods=['POST'])
def add_entry():
    if not session.get('logged_in'):
        abort(401)
    db = get_db()
    db.execute('insert into entries (title, text) values (?, ?)',
               [request.form['title'], request.form['text']])
    db.commit()
    
    return "Done"    
    
@app.route('/')
def index():
    return render_template('index.html')
    
 
        
@app.route('/register', methods=['POST'])
def register():
    request.get_data(parse_form_data=False, cache=True)
    bid = request.form.get('BidNumber', default='0')
    msg = request.form.get('Msg', default='').replace(' ','+')
    result = check_register(msg)
    url = 'http://127.0.0.1:5000/static/qrcode/pay.png'
    if bid in result and len(result.split('#')) == 3:
        app.logger.debug("BID CHECK PASS")
        number = result.split('#')[0]
        mouth  = result.split('#')[1]
        phone  = result.split('#')[2]
        if mouth == '0':
            url = 'http://127.0.0.1:5000/static/qrcode/1001.png'
        elif mouth == '1':
            url = 'http://127.0.0.1:5000/static/qrcode/2001.png'
        elif mouth == '2':
            url = 'http://127.0.0.1:5000/static/qrcode/3001.png'
        elif mouth == '3':
            url = 'http://127.0.0.1:5000/static/qrcode/4001.png'

    return url
   

@app.route('/upload', methods=['POST'])
def upload():
    upload_file = request.files['image01']
    if upload_file and allowed_file(upload_file.filename):
        filename = secure_filename(upload_file.filename)
        upload_file.save(os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename))
        return 'hello, '+request.form.get('name', 'little apple')+'. success'
    else:
        return 'hello, '+request.form.get('name', 'little apple')+'. failed'
        
@app.route('/hello/')
@app.route('/hello/<name>')
def hello(name=None):
    return render_template('hello.html', name=name)     
        
if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'
    app.run()