"""Public service, isolated from the private Grocy instance."""
import base64, hashlib, hmac, json, os, secrets, time
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit
from flask import Flask, g, request, jsonify, send_from_directory
from sqlalchemy import select, insert, update, delete, and_, text as sql_text
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException
from . import db, __version__
from .security import (Error, Vault, opaque, digest, csrf, canonical, secret_file,
                       text, bounds, integer)

class Service:
    def __init__(self,app):
        self.app=app;self.config=app.config
        url=self.config.get('DATABASE_URL')
        if not url:url=Path(self.config['DATABASE_URL_FILE']).read_text().strip()
        self.db=db.engine(url)
        self.secret=secret_file(self.config['SEAL_KEY_FILE'])
        self.vault=Vault(self.secret)
        self.origin=self.config['PUBLIC_ORIGIN'].rstrip('/')
        parsed=urlsplit(self.origin)
        if parsed.scheme!='https' and not (self.config.get('TESTING') or parsed.hostname in ('localhost','127.0.0.1')):
            raise RuntimeError('Origine publique HTTPS requise')
        self.public_key=base64.b64decode(Path(self.config['DATA_PUBLIC_KEY_FILE']).read_text().strip())
        if len(self.public_key)!=32:raise RuntimeError('Clé publique invalide')
        self.data=Path(self.config['STATE_DIR']);self.data.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.dummy_password=self.config.get('DUMMY_PASSWORD')
        if not self.dummy_password:
            from .security import PASSWORDS
            self.dummy_password=PASSWORDS.hash(opaque())

    def body(self,allowed=None,required=()):
        if not request.is_json:raise Error('JSON requis',415)
        value=request.get_json(silent=True)
        if not isinstance(value,dict):raise Error('JSON invalide')
        bounds(value)
        if allowed is not None and (set(value)-set(allowed) or set(required)-set(value)):raise Error('Champs absents ou inconnus')
        return value

    def rate(self,purpose,limit=15,interval=60,identity=None):
        # Forwarded IP is trusted only from the configured reverse proxy address.
        remote=request.remote_addr or 'unknown'
        if remote in self.config.get('TRUSTED_PROXIES',()):
            forwarded=request.headers.get('X-Forwarded-For','').split(',')[0].strip()
            import ipaddress
            try:remote=str(ipaddress.ip_address(forwarded))
            except ValueError:pass
        key=digest(purpose+'|'+(identity or remote));window=int(time.time()//interval)
        with self.db.begin() as conn:
            self.lock(conn,'rate:'+key)
            existing=db.row(conn,db.limits,db.limits.c.key==key)
            count=existing['count']+1 if existing and existing['window']==window else 1
            if existing:conn.execute(update(db.limits).where(db.limits.c.key==key).values(window=window,count=count))
            else:conn.execute(insert(db.limits).values(key=key,window=window,count=count))
        if count>limit:raise Error('Trop de tentatives ; réessayer plus tard',429,'rate_limited')

    def lock(self,conn,key):
        if conn.dialect.name=='postgresql':
            number=int.from_bytes(hashlib.sha256(key.encode()).digest()[:8],'big',signed=True)
            conn.execute(sql_text('SELECT pg_advisory_xact_lock(:key)'),{'key':number})

    def current(self):
        sid=request.cookies.get('grocyste_community','')
        if len(sid)>100:sid=''
        g.sid=sid;g.user=None;g.session=None;g.grant=None
        with self.db.begin() as conn:
            authorization=request.headers.get('Authorization','')
            if authorization:
                if not authorization.startswith('Bearer ') or len(authorization)>200:raise Error('Accès refusé',401)
                grant=db.row(conn,db.grants,db.grants.c.access_hash==digest(authorization[7:]))
                if not grant or grant['expires']<time.time():raise Error('Association expirée',401)
                g.grant=grant;g.user=db.row(conn,db.users,db.users.c.id==grant['user_id'])
            elif sid:
                session=db.row(conn,db.sessions,db.sessions.c.hash==digest(sid))
                if session and session['expires']>time.time() and session['touched']>time.time()-3600:
                    g.session=session
                    if session['user_id']:g.user=db.row(conn,db.users,db.users.c.id==session['user_id'])
                    conn.execute(update(db.sessions).where(db.sessions.c.hash==digest(sid)).values(touched=time.time()))
            if g.user and g.user['status'] in ('suspended','deleted'):
                g.user=None;g.session=None;g.grant=None

    def origin_guard(self):
        if request.method in ('GET','HEAD','OPTIONS'):return
        if g.grant:
            if request.headers.get('Origin') not in (None,self.origin):raise Error('Origine refusée',403)
            return
        if request.path in ('/api/v1/oauth/device','/api/v1/oauth/token'):
            if request.headers.get('Origin') not in (None,self.origin):raise Error('Origine refusée',403)
            return
        if request.headers.get('Origin')!=self.origin:raise Error('Origine refusée',403,'origin_denied')
        supplied=request.headers.get('X-CSRF-Token','')
        if not g.session or not hmac.compare_digest(supplied,csrf(self.secret,g.sid)):
            raise Error('Session ou protection CSRF manquante',403,'csrf_denied')

    def actor(self,*,roles=None,verified=True,grants=True):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*a,**kw):
                if not g.user:raise Error('Connexion requise',401)
                if verified and g.user['status']!='active':raise Error('Valider votre email avant cette action',403)
                if g.grant and (not grants or 'community.write' not in g.grant['scope'].split()):raise Error('Autorisation insuffisante',403)
                if roles:
                    if g.grant or g.user['role'] not in roles:raise Error('Rôle insuffisant',403)
                    if not g.session['mfa']:raise Error('Double authentification requise',403,'mfa_required')
                return fn(*a,**kw)
            return wrapper
        return decorator

    def mutate(self,fn):
        @wraps(fn)
        def wrapped(*a,**kw):
            if not g.user:raise Error('Connexion requise',401)
            key=request.headers.get('Idempotency-Key','')
            import re
            if not re.fullmatch(r'[A-Za-z0-9_.:-]{8,80}',key):raise Error('Clé d’idempotence requise')
            body=self.body();fingerprint=digest(canonical({'path':request.path,'method':request.method,'body':body}))
            with self.db.begin() as conn:
                current=conn.execute(select(db.users).where(db.users.c.id==g.user['id']).with_for_update()).mappings().first()
                if not current or current['status']!='active' or current['role']!=g.user['role']:
                    raise Error('Les permissions ont changé ; reconnectez-vous',403)
                if g.grant:
                    valid=db.row(conn,db.grants,db.grants.c.access_hash==g.grant['access_hash'])
                else:
                    valid=db.row(conn,db.sessions,db.sessions.c.hash==digest(g.sid))
                if not valid:raise Error('Session révoquée',401)
                self.lock(conn,'operation:'+g.user['id']+':'+key)
                existing=db.row(conn,db.operations,and_(db.operations.c.actor==g.user['id'],db.operations.c.key==key))
                if existing:
                    if existing['request_hash']!=fingerprint:raise Error('Clé déjà utilisée pour une autre action',409)
                    return jsonify(existing['response']),existing['status']
                result=fn(conn,body,*a,**kw)
                payload,status=result if isinstance(result,tuple) else (result,200)
                conn.execute(insert(db.operations).values(actor=g.user['id'],key=key,request_hash=fingerprint,response=payload,status=status,created=time.time()))
                return jsonify(payload),status
        return wrapped

    def session(self,conn,user_id=None,mfa=False):
        if g.sid:conn.execute(delete(db.sessions).where(db.sessions.c.hash==digest(g.sid)))
        sid=opaque();now=time.time()
        conn.execute(insert(db.sessions).values(hash=digest(sid),user_id=user_id,created=now,touched=now,expires=now+43200,mfa=mfa))
        g.new_sid=sid;return sid

    def audit(self,conn,action,target=None,details=None,actor=None):
        conn.execute(insert(db.audit).values(id=db.uid(),actor=actor or (g.user['id'] if getattr(g,'user',None) else None),action=action,target=target,details=details or {},created=time.time()))

    def issue_token(self,conn,user_id,kind,payload=None,seconds=3600):
        conn.execute(update(db.tokens).where(and_(db.tokens.c.user_id==user_id,db.tokens.c.kind==kind,db.tokens.c.used==False)).values(used=True))
        token=opaque()
        conn.execute(insert(db.tokens).values(hash=digest(token),user_id=user_id,kind=kind,payload=payload or {},expires=time.time()+seconds,used=False))
        return token

    def token(self,conn,value,kind):
        if not isinstance(value,str) or len(value)>100:raise Error('Lien invalide ou expiré')
        token=conn.execute(select(db.tokens).where(and_(db.tokens.c.hash==digest(value),db.tokens.c.kind==kind)).with_for_update()).mappings().first()
        if not token or token['used'] or token['expires']<time.time():raise Error('Lien invalide ou expiré')
        return token

    def mail(self,conn,recipient,kind,params,key):
        mail_id=digest(kind+':'+key)
        if db.row(conn,db.outbox,db.outbox.c.id==mail_id):return
        conn.execute(insert(db.outbox).values(id=mail_id,payload=self.vault.seal({'to':recipient,'kind':kind,'params':params}),state='pending',attempts=0,next_attempt=time.time()))

    def notify(self,conn,user_id,kind,message,entry_id=None):
        conn.execute(insert(db.notifications).values(id=db.uid(),user_id=user_id,kind=kind,message=message,entry_id=entry_id,created=time.time(),read=False))
        user=db.row(conn,db.users,db.users.c.id==user_id)
        if user and user['email'] and user['status']=='active' and user['preferences'].get('email_notifications',False):
            self.mail(conn,user['email'],'notification',{'message':message,'entry_id':entry_id},db.uid())

    def public_user(self,user):
        return {'id':user['id'],'name':user['name'],'bio':user['bio'],'created_at':user['created']}

def create_app(config=None):
    app=Flask(__name__,static_folder=None)
    root=Path(os.environ.get('STATE_DIR','state')).resolve()
    app.config.update(PUBLIC_ORIGIN=os.environ.get('PUBLIC_ORIGIN','https://grocyste.banane.fun'),
        STATE_DIR=str(root),SEAL_KEY_FILE=os.environ.get('SEAL_KEY_FILE',str(root/'secrets/seal.key')),
        DATA_PUBLIC_KEY_FILE=os.environ.get('DATA_PUBLIC_KEY_FILE',str(root/'data-signing.pub')),
        DATABASE_URL_FILE=os.environ.get('DATABASE_URL_FILE','/run/secrets/database-url'),
        SIGNUPS_OPEN=os.environ.get('SIGNUPS_OPEN','false')=='true',MAX_CONTENT_LENGTH=16*1024*1024,
        TRUSTED_PROXIES=tuple(os.environ.get('TRUSTED_PROXIES','').split(',')),
        WEB_DIR=os.environ.get('WEB_DIR',str(Path(__file__).resolve().parent.parent/'web')),
        SMTP_HOST=os.environ.get('SMTP_HOST','mail.laureillard.fr'),SMTP_PORT=587,
        SMTP_LOGIN_FILE=os.environ.get('SMTP_LOGIN_FILE','/run/secrets/smtp.json'),
        SENDER='grocyste@banane.fun')
    if config:app.config.update(config)
    service=Service(app);app.extensions['community']=service
    if app.config.get('TESTING'):db.migrate(service.db)

    @app.before_request
    def protect():
        g.new_sid=None
        service.current()
        if request.path.startswith('/api/v1/'):
            service.rate('api',180)
            service.origin_guard()

    @app.after_request
    def headers(response):
        response.headers.update({'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
            'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'",
            'Permissions-Policy':'camera=(), microphone=(), geolocation=()','X-Frame-Options':'DENY'})
        if request.path.startswith('/api/v1/') or request.path in ('/setup','/verify','/reset','/authorize'):
            response.headers['Cache-Control']='no-store'
        if getattr(g,'new_sid',None):
            response.set_cookie('grocyste_community',g.new_sid,httponly=True,secure=service.origin.startswith('https:'),samesite='Strict',path='/',max_age=43200)
        return response

    @app.errorhandler(Error)
    def error(exc):return jsonify(ok=False,error={'code':exc.code,'message':str(exc)}),exc.status
    @app.errorhandler(HTTPException)
    def http_error(exc):return jsonify(ok=False,error={'code':'http_error','message':'Requête refusée'}),exc.code
    @app.errorhandler(IntegrityError)
    def conflict(exc):return jsonify(ok=False,error={'code':'conflict','message':'Cette opération entre en conflit avec une autre modification'}),409
    @app.errorhandler(Exception)
    def unexpected(exc):
        app.logger.error('Community internal error: %s',type(exc).__name__)
        return jsonify(ok=False,error={'code':'internal_error','message':'Opération interrompue ; consulter son état avant de réessayer'}),500

    @app.get('/api/v1/health')
    def health():
        with service.db.connect() as conn:conn.execute(select(db.schema_versions.c.version)).scalar_one()
        return jsonify(ok=True,version=__version__)

    @app.get('/api/v1/public-config')
    def public_config():return jsonify(ok=True,version=__version__,origin=service.origin,signups_open=service.config['SIGNUPS_OPEN'],data_key=base64.b64encode(service.public_key).decode(),data_key_id=digest(service.public_key))

    @app.get('/assets/<path:name>')
    def assets(name):
        if name not in ('app.mjs','app.css'):raise Error('Ressource inconnue',404)
        return send_from_directory(service.config['WEB_DIR'],name)

    @app.get('/')
    @app.get('/login')
    @app.get('/register')
    @app.get('/verify')
    @app.get('/reset')
    @app.get('/setup')
    @app.get('/authorize')
    @app.get('/account')
    @app.get('/moderation')
    @app.get('/entry/<entry_id>')
    @app.get('/profile/<user_id>')
    def page(**kw):return send_from_directory(service.config['WEB_DIR'],'index.html')

    from .accounts import register as accounts
    from .routes import register as routes
    from .device import register as device
    accounts(app,service);routes(app,service);device(app,service)
    return app
