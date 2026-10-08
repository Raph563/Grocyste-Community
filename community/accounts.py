"""Email-verified accounts, session revocation and mandatory staff MFA."""
import base64, hmac, secrets, time
from flask import g, request, jsonify
from sqlalchemy import select, insert, update, delete, and_, func
from . import db
from .security import Error, text, email, password, verify_password, normalized, digest, csrf, opaque, totp_counter

ACCEPTED={'ok':True,'message':'Si cette demande peut être traitée, un email vous sera envoyé.'}

def register(app,s):
    @app.get('/api/v1/session')
    def session():
        if not g.session and not g.grant:
            with s.db.begin() as conn:sid=s.session(conn)
        else:sid=g.sid
        user=None
        if g.user:
            user={**s.public_user(g.user),'email':g.user['email'],'role':g.user['role'],
                  'status':g.user['status'],'preferences':g.user['preferences'],
                  'totp_enabled':bool(g.user['totp']),'mfa_verified':bool(g.session and g.session['mfa'])}
        return jsonify(ok=True,user=user,csrf_token=csrf(s.secret,sid) if sid else None,signups_open=s.config['SIGNUPS_OPEN'])

    @app.post('/api/v1/auth/register')
    def signup():
        if not s.config['SIGNUPS_OPEN']:raise Error('Les inscriptions ouvriront après validation de la plateforme',403)
        s.rate('signup',5,3600)
        b=s.body({'name','email','password'},{'name','email','password'})
        address=email(b['email']);name=text(b['name'],80,2);encoded=password(b['password'])
        key=normalized(name)
        if len(key)<2:raise Error('Pseudonyme invalide')
        with s.db.begin() as conn:
            s.lock(conn,'account:'+address)
            if db.row(conn,db.users,(db.users.c.email==address)|(db.users.c.name_key==key)):return jsonify(ACCEPTED),202
            user_id=db.uid();conn.execute(insert(db.users).values(id=user_id,email=address,name=name,name_key=key,password=encoded,role='member',status='unverified',created=time.time(),bio='',preferences={},recovery=[],totp_counter=-1))
            token=s.issue_token(conn,user_id,'verify',seconds=86400)
            s.mail(conn,address,'verify',{'token':token},digest(token));s.audit(conn,'account.register',user_id,actor=user_id)
        return jsonify(ACCEPTED),202

    @app.post('/api/v1/auth/setup')
    def setup():
        s.rate('setup',10,3600)
        b=s.body({'token','email','password'},{'token','email','password'})
        address=email(b['email']);encoded=password(b['password'])
        with s.db.begin() as conn:
            token=s.token(conn,b['token'],'invite');user=db.row(conn,db.users,db.users.c.id==token['user_id'])
            if not user or user['status']!='invited':raise Error('Invitation déjà utilisée')
            conn.execute(update(db.users).where(db.users.c.id==user['id']).values(email=address,password=encoded,status='unverified'))
            conn.execute(update(db.tokens).where(db.tokens.c.hash==token['hash']).values(used=True))
            verify=s.issue_token(conn,user['id'],'verify',seconds=86400)
            s.mail(conn,address,'verify',{'token':verify},digest(verify));s.audit(conn,'account.invitation.claimed',user['id'],actor=user['id'])
        return jsonify(ACCEPTED),202

    @app.post('/api/v1/auth/verify')
    def verify():
        s.rate('verify',12)
        b=s.body({'token'},{'token'})
        with s.db.begin() as conn:
            token=s.token(conn,b['token'],'verify');user=db.row(conn,db.users,db.users.c.id==token['user_id'])
            if user['status']!='unverified':raise Error('Lien invalide ou compte indisponible')
            conn.execute(update(db.users).where(db.users.c.id==user['id']).values(status='active'))
            conn.execute(update(db.tokens).where(db.tokens.c.hash==token['hash']).values(used=True))
            s.audit(conn,'account.verified',user['id'],actor=user['id'])
        return jsonify(ok=True,message='Adresse validée. Vous pouvez vous connecter.')

    @app.post('/api/v1/auth/resend')
    def resend():
        s.rate('resend',4,3600);b=s.body({'email'},{'email'});address=email(b['email'])
        s.rate('resend-address',3,3600,identity=digest(address))
        with s.db.begin() as conn:
            s.lock(conn,'account:'+address);user=db.row(conn,db.users,db.users.c.email==address)
            if user and user['status']=='unverified':
                token=s.issue_token(conn,user['id'],'verify',seconds=86400);s.mail(conn,address,'verify',{'token':token},digest(token))
        return jsonify(ACCEPTED),202

    @app.post('/api/v1/auth/login')
    def login():
        s.rate('login',12);b=s.body({'email','password'},{'email','password'});address=email(b['email'])
        s.rate('login-address',15,300,identity=digest(address))
        with s.db.begin() as conn:
            user=db.row(conn,db.users,db.users.c.email==address)
            valid=verify_password(user['password'] if user and user['password'] else s.dummy_password,b['password'])
            if not valid or not user or user['status'] not in ('active','unverified'):raise Error('Connexion refusée',401)
            sid=s.session(conn,user['id']);s.audit(conn,'account.login',user['id'],actor=user['id'])
        return jsonify(ok=True,csrf_token=csrf(s.secret,sid),mfa_required=bool(user['totp']) or user['role']!='member')

    @app.post('/api/v1/auth/logout')
    def logout():
        with s.db.begin() as conn:
            if g.session:conn.execute(delete(db.sessions).where(db.sessions.c.hash==digest(g.sid)))
            s.session(conn)
        return jsonify(ok=True)

    @app.post('/api/v1/auth/recover')
    def recover():
        s.rate('recover',4,3600);b=s.body({'email'},{'email'});address=email(b['email'])
        s.rate('recover-address',3,3600,identity=digest(address))
        with s.db.begin() as conn:
            s.lock(conn,'account:'+address);user=db.row(conn,db.users,db.users.c.email==address)
            if user and user['status']=='active':
                token=s.issue_token(conn,user['id'],'reset');s.mail(conn,address,'reset',{'token':token},digest(token))
        return jsonify(ACCEPTED),202

    @app.post('/api/v1/auth/reset')
    def reset():
        s.rate('reset',10);b=s.body({'token','password'},{'token','password'});encoded=password(b['password'])
        with s.db.begin() as conn:
            token=s.token(conn,b['token'],'reset');user=db.row(conn,db.users,db.users.c.id==token['user_id'])
            if user['status']!='active':raise Error('Compte indisponible')
            conn.execute(update(db.users).where(db.users.c.id==user['id']).values(password=encoded))
            revoke_all(conn,user['id']);s.audit(conn,'account.password.reset',user['id'],actor=user['id'])
            s.mail(conn,user['email'],'security',{'message':'Votre mot de passe a été changé. Toutes les sessions et associations ont été fermées.'},db.uid())
        return jsonify(ok=True,message='Mot de passe changé. Reconnectez-vous ; la double authentification reste requise.')

    @app.post('/api/v1/auth/totp/setup')
    @s.actor(grants=False)
    def totp_setup():
        b=s.body({'password'},{'password'})
        if not verify_password(g.user['password'],b['password']):raise Error('Réauthentification refusée',403)
        if g.user['totp'] and not g.session['mfa']:raise Error('Double authentification requise',403)
        secret=base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
        with s.db.begin() as conn:conn.execute(update(db.users).where(db.users.c.id==g.user['id']).values(totp_pending=s.vault.seal(secret)))
        from urllib.parse import quote
        return jsonify(ok=True,secret=secret,uri='otpauth://totp/Grocyste:'+quote(g.user['name'])+'?secret='+secret+'&issuer=Grocyste')

    @app.post('/api/v1/auth/totp/enable')
    @s.actor(grants=False)
    def totp_enable():
        s.rate('totp',10);b=s.body({'code'},{'code'})
        with s.db.begin() as conn:
            user=conn.execute(select(db.users).where(db.users.c.id==g.user['id']).with_for_update()).mappings().one()
            if not user['totp_pending']:raise Error('Configurer la double authentification auparavant')
            secret=s.vault.open(user['totp_pending']);counter=totp_counter(secret,b['code'])
            if counter is None:raise Error('Code refusé',403)
            recovery=[secrets.token_hex(10) for _ in range(10)]
            conn.execute(update(db.users).where(db.users.c.id==user['id']).values(totp=user['totp_pending'],totp_pending=None,totp_counter=counter,recovery=[digest(v) for v in recovery]))
            conn.execute(update(db.sessions).where(db.sessions.c.hash==digest(g.sid)).values(mfa=True));s.audit(conn,'account.mfa.enabled',user['id'])
        return jsonify(ok=True,recovery_codes=recovery)

    @app.post('/api/v1/auth/totp/verify')
    @s.actor(grants=False)
    def totp_verify():
        s.rate('totp',10);b=s.body({'code'},{'code'})
        with s.db.begin() as conn:
            user=conn.execute(select(db.users).where(db.users.c.id==g.user['id']).with_for_update()).mappings().one()
            if not user['totp']:raise Error('Configurer la double authentification auparavant')
            counter=totp_counter(s.vault.open(user['totp']),b['code'],user['totp_counter'])
            recovery=list(user['recovery']);recovery_hash=digest(text(b['code'],100))
            used=next((v for v in recovery if hmac.compare_digest(v,recovery_hash)),None)
            if counter is None and not used:raise Error('Code refusé',403)
            if used:recovery.remove(used)
            conn.execute(update(db.users).where(db.users.c.id==user['id']).values(totp_counter=counter if counter is not None else user['totp_counter'],recovery=recovery))
            conn.execute(update(db.sessions).where(db.sessions.c.hash==digest(g.sid)).values(mfa=True))
        return jsonify(ok=True)

    @app.put('/api/v1/account')
    @s.actor(grants=False)
    def profile():
        b=s.body({'bio','preferences'},{'bio','preferences'});bio=text(b['bio'],2000)
        prefs=b['preferences']
        if not isinstance(prefs,dict) or set(prefs)-{'email_notifications'} or any(type(v) is not bool for v in prefs.values()):raise Error('Réglages invalides')
        with s.db.begin() as conn:conn.execute(update(db.users).where(db.users.c.id==g.user['id']).values(bio=bio,preferences=prefs))
        return jsonify(ok=True)

    @app.post('/api/v1/account/email')
    @s.actor(grants=False)
    def change_email():
        s.rate('change-email',3,3600);b=s.body({'email','password'},{'email','password'});address=email(b['email'])
        if not verify_password(g.user['password'],b['password']) or (g.user['totp'] and not g.session['mfa']):raise Error('Réauthentification refusée',403)
        with s.db.begin() as conn:
            if db.row(conn,db.users,db.users.c.email==address):return jsonify(ACCEPTED),202
            token=s.issue_token(conn,g.user['id'],'email-change',{'email':address})
            s.mail(conn,address,'email-change',{'token':token},digest(token))
            s.mail(conn,g.user['email'],'security',{'message':'Un changement de votre adresse email a été demandé.'},db.uid())
        return jsonify(ACCEPTED),202

    @app.post('/api/v1/account/email/confirm')
    @s.actor(grants=False)
    def confirm_email():
        b=s.body({'token'},{'token'})
        with s.db.begin() as conn:
            token=s.token(conn,b['token'],'email-change')
            if token['user_id']!=g.user['id']:raise Error('Lien refusé',403)
            conn.execute(update(db.users).where(db.users.c.id==g.user['id']).values(email=token['payload']['email']))
            revoke_all(conn,g.user['id']);s.audit(conn,'account.email.changed',g.user['id'])
        return jsonify(ok=True,message='Adresse changée ; reconnectez-vous.')

    @app.get('/api/v1/account/sessions')
    @s.actor(grants=False)
    def account_sessions():
        with s.db.connect() as conn:
            values=conn.execute(select(db.sessions.c.hash,db.sessions.c.created,db.sessions.c.touched,db.sessions.c.expires).where(db.sessions.c.user_id==g.user['id'])).mappings().all()
            linked=conn.execute(select(db.grants.c.id,db.grants.c.instance,db.grants.c.created,db.grants.c.refresh_expires).where(db.grants.c.user_id==g.user['id'])).mappings().all()
        return jsonify(ok=True,sessions=[dict(v,current=v['hash']==digest(g.sid)) for v in values],associations=[dict(v) for v in linked])

    @app.delete('/api/v1/account/sessions/<session_hash>')
    @s.actor(grants=False)
    def revoke_session(session_hash):
        with s.db.begin() as conn:conn.execute(delete(db.sessions).where(and_(db.sessions.c.user_id==g.user['id'],db.sessions.c.hash==session_hash)))
        return jsonify(ok=True)

    @app.delete('/api/v1/account/associations/<grant_id>')
    @s.actor(grants=False)
    def revoke_association(grant_id):
        with s.db.begin() as conn:conn.execute(delete(db.grants).where(and_(db.grants.c.user_id==g.user['id'],db.grants.c.id==grant_id)))
        return jsonify(ok=True)

    @app.get('/api/v1/account/export')
    @s.actor(grants=False)
    def export():
        with s.db.connect() as conn:
            contributions=conn.execute(select(db.entries.c.id,db.entries.c.kind,db.revisions.c.revision,db.revisions.c.state,db.revisions.c.content).join(db.revisions,db.entries.c.id==db.revisions.c.id).where(db.entries.c.owner_id==g.user['id'])).mappings().all()
            own_comments=conn.execute(select(db.comments.c.entry_id,db.comments.c.text,db.comments.c.state,db.comments.c.created).where(db.comments.c.user_id==g.user['id'])).mappings().all()
            own_favorites=conn.execute(select(db.favorites.c.entry_id).where(db.favorites.c.user_id==g.user['id'])).scalars().all()
        response=jsonify(schema='grocyste-account-export-v1',profile={**s.public_user(g.user),'email':g.user['email'],'preferences':g.user['preferences']},contributions=[dict(v) for v in contributions],comments=[dict(v) for v in own_comments],favorites=own_favorites)
        response.headers['Content-Disposition']='attachment; filename="grocyste-compte.json"';return response

    @app.delete('/api/v1/account')
    @s.actor(grants=False)
    def remove_account():
        b=s.body({'password'},{'password'})
        if not verify_password(g.user['password'],b['password']) or (g.user['totp'] and not g.session['mfa']):raise Error('Réauthentification refusée',403)
        with s.db.begin() as conn:
            s.lock(conn,'staff-roles')
            if g.user['role']=='admin' and conn.execute(select(func.count()).select_from(db.users).where(and_(db.users.c.role=='admin',db.users.c.status=='active'))).scalar()<2:raise Error('Désigner un autre administrateur avant de supprimer ce compte',409)
            revoke_all(conn,g.user['id'])
            conn.execute(update(db.users).where(db.users.c.id==g.user['id']).values(email=None,password=None,status='deleted',role='member',name='Contributeur supprimé',name_key='deleted-'+g.user['id'],bio='',totp=None,totp_pending=None,recovery=[],preferences={}))
            conn.execute(delete(db.favorites).where(db.favorites.c.user_id==g.user['id']));conn.execute(delete(db.subscriptions).where(db.subscriptions.c.user_id==g.user['id']))
            s.audit(conn,'account.deleted',g.user['id'])
        return jsonify(ok=True,message='Compte supprimé. Les contenus déjà publiés conservent leur licence ; demander leur retrait via les signalements.')

def revoke_all(conn,user_id):
    conn.execute(delete(db.sessions).where(db.sessions.c.user_id==user_id))
    conn.execute(delete(db.grants).where(db.grants.c.user_id==user_id))
    conn.execute(update(db.tokens).where(db.tokens.c.user_id==user_id).values(used=True))
