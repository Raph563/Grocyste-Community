"""RFC 8628 linking: grants are obtained by the CORE, not the Grocy browser."""
import secrets,time
from flask import g,jsonify
from sqlalchemy import select,insert,update,delete,and_
from . import db
from .security import Error,opaque,digest,text,public_url

def register(app,s):
    @app.post('/api/v1/oauth/device')
    def start():
        s.rate('device-start',8)
        b=s.body({'client_id','instance','scope'},{'client_id','instance'})
        if b['client_id']!='grocyste-core':raise Error('Client inconnu')
        instance=public_url(b['instance'],nullable=False)
        if b.get('scope','community.read community.write')!='community.read community.write':raise Error('Portée refusée')
        secret=opaque();code=''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(10))
        with s.db.begin() as conn:
            conn.execute(insert(db.devices).values(hash=digest(secret),code_hash=digest(code),instance=instance,scope='community.read community.write',expires=time.time()+600,last_poll=0,state='pending'))
        return jsonify(device_code=secret,user_code=code,verification_uri=s.origin+'/authorize',verification_uri_complete=s.origin+'/authorize#code='+code,expires_in=600,interval=5)

    @app.post('/api/v1/oauth/approve')
    @s.actor(grants=False)
    def approve():
        s.rate('device-approve',10)
        b=s.body({'user_code','approve'},{'user_code','approve'})
        code=text(b['user_code'],20).replace('-','').replace(' ','').upper()
        if type(b['approve']) is not bool:raise Error('Décision requise')
        with s.db.begin() as conn:
            value=conn.execute(select(db.devices).where(db.devices.c.code_hash==digest(code)).with_for_update()).mappings().first()
            if not value or value['expires']<time.time() or value['state']!='pending':raise Error('Code invalide ou expiré')
            conn.execute(update(db.devices).where(db.devices.c.hash==value['hash']).values(user_id=g.user['id'],state='approved' if b['approve'] else 'denied'))
            s.audit(conn,'association.approved' if b['approve'] else 'association.denied',details={'instance':value['instance']})
        return jsonify(ok=True,instance=value['instance'])

    @app.post('/api/v1/oauth/inspect')
    @s.actor(grants=False)
    def inspect():
        s.rate('device-inspect',15)
        b=s.body({'user_code'},{'user_code'});code=text(b['user_code'],20).replace('-','').replace(' ','').upper()
        with s.db.connect() as conn:value=db.row(conn,db.devices,db.devices.c.code_hash==digest(code))
        if not value or value['expires']<time.time() or value['state']!='pending':raise Error('Code invalide ou expiré')
        return jsonify(ok=True,instance=value['instance'],scope=value['scope'],user_code=code)

    @app.post('/api/v1/oauth/token')
    def token():
        s.rate('device-token',60)
        b=s.body({'client_id','grant_type','device_code','refresh_token'},{'client_id','grant_type'})
        if b['client_id']!='grocyste-core':raise Error('Client inconnu')
        with s.db.begin() as conn:
            if b['grant_type']=='urn:ietf:params:oauth:grant-type:device_code':
                secret=text(b.get('device_code'),100,20)
                value=conn.execute(select(db.devices).where(db.devices.c.hash==digest(secret)).with_for_update()).mappings().first()
                if not value or value['expires']<time.time():raise Error('expired_token',400,'expired_token')
                if value['last_poll']>time.time()-4:raise Error('slow_down',400,'slow_down')
                conn.execute(update(db.devices).where(db.devices.c.hash==value['hash']).values(last_poll=time.time()))
                if value['state']=='pending':return jsonify(error={'code':'authorization_pending','message':'Autorisation en attente'}),400
                if value['state']!='approved':raise Error('access_denied',400,'access_denied')
                user=db.row(conn,db.users,db.users.c.id==value['user_id'])
                if not user or user['status']!='active':raise Error('access_denied',400,'access_denied')
                conn.execute(update(db.devices).where(db.devices.c.hash==value['hash']).values(state='consumed'))
                grant_id=db.uid();user_id=value['user_id'];instance=value['instance'];scope=value['scope']
            elif b['grant_type']=='refresh_token':
                value=conn.execute(select(db.grants).where(db.grants.c.refresh_hash==digest(text(b.get('refresh_token'),100,20))).with_for_update()).mappings().first()
                if not value or value['refresh_expires']<time.time():raise Error('invalid_grant',400,'invalid_grant')
                user=db.row(conn,db.users,db.users.c.id==value['user_id'])
                if not user or user['status']!='active':raise Error('invalid_grant',400,'invalid_grant')
                grant_id=value['id'];user_id=value['user_id'];instance=value['instance'];scope=value['scope']
                conn.execute(delete(db.grants).where(db.grants.c.id==grant_id))
            else:raise Error('unsupported_grant_type',400,'unsupported_grant_type')
            access=opaque();refresh=opaque()
            conn.execute(insert(db.grants).values(id=grant_id,user_id=user_id,access_hash=digest(access),refresh_hash=digest(refresh),scope=scope,instance=instance,expires=time.time()+900,refresh_expires=time.time()+30*86400,created=time.time()))
        return jsonify(access_token=access,refresh_token=refresh,token_type='Bearer',expires_in=900,scope=scope)
