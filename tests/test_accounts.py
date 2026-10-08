import time
from sqlalchemy import select,update
from community import db
from community.security import digest,totp
from conftest import call

def anonymous(app):
    c=app.test_client();r=c.get('/api/v1/session',base_url='https://community.test')
    assert r.status_code==200,r.json
    return c,{'Origin':'https://community.test','X-CSRF-Token':r.json['csrf_token'],'Idempotency-Key':db.uid()}

def queued_token(app,kind):
    s=app.extensions['community']
    with s.db.connect() as conn:
        for row in conn.execute(select(db.outbox)).mappings():
            value=s.vault.open(row['payload'])
            if value['kind']==kind:return value['params']['token']
    raise AssertionError('No queued token')

def test_signup_verify_reset_revokes_sessions(app):
    c,h=anonymous(app)
    b={'name':'Synthétique','email':'new@example.test','password':'synthetic new password'}
    assert call(c,'/api/v1/auth/register',h,data=b).status_code==202
    token=queued_token(app,'verify')
    # Merely visiting the URL does not consume a scanner-followed validation link.
    assert c.get('/verify',base_url='https://community.test').status_code==200
    assert call(c,'/api/v1/auth/verify',h,data={'token':token}).status_code==200
    assert call(c,'/api/v1/auth/verify',h,data={'token':token}).status_code==400
    r=call(c,'/api/v1/auth/login',h,data={'email':b['email'],'password':b['password']});assert r.status_code==200,r.json
    h['X-CSRF-Token']=r.json['csrf_token']
    assert c.get('/api/v1/contributions',base_url='https://community.test').status_code==200
    assert call(c,'/api/v1/auth/recover',h,data={'email':b['email']}).status_code==202
    reset=queued_token(app,'reset')
    assert call(c,'/api/v1/auth/reset',h,data={'token':reset,'password':'replacement synthetic password'}).status_code==200
    assert c.get('/api/v1/contributions',base_url='https://community.test').status_code==401

def test_recovery_and_registration_do_not_enumerate_accounts(app,clients):
    c,h=anonymous(app)
    a=call(c,'/api/v1/auth/recover',h,data={'email':'alice@example.test'})
    b=call(c,'/api/v1/auth/recover',h,data={'email':'missing@example.test'})
    assert a.status_code==b.status_code==202 and a.json==b.json
    own=call(c,'/api/v1/auth/register',h,data={'name':'New','email':'alice@example.test','password':'synthetic long password'})
    fresh=call(c,'/api/v1/auth/register',h,data={'name':'Newer','email':'other@example.test','password':'synthetic long password'})
    assert own.status_code==fresh.status_code==202 and own.json==fresh.json

def test_expired_tokens_and_secure_cookie(app):
    c,h=anonymous(app);call(c,'/api/v1/auth/register',h,data={'name':'Expiry','email':'expire@example.test','password':'synthetic long password'})
    token=queued_token(app,'verify');s=app.extensions['community']
    with s.db.begin() as conn:conn.execute(update(db.tokens).where(db.tokens.c.hash==digest(token)).values(expires=time.time()-1))
    assert call(c,'/api/v1/auth/verify',h,data={'token':token}).status_code==400
    c2=app.test_client();r=c2.get('/api/v1/session',base_url='https://community.test');cookie=r.headers['Set-Cookie']
    assert 'HttpOnly' in cookie and 'Secure' in cookie and 'SameSite=Strict' in cookie

def test_invitation_never_first_signup_becomes_admin(app):
    c,h=anonymous(app);call(c,'/api/v1/auth/register',h,data={'name':'First','email':'first@example.test','password':'synthetic long password'})
    s=app.extensions['community']
    with s.db.connect() as conn:user=conn.execute(select(db.users).where(db.users.c.email=='first@example.test')).mappings().one()
    assert user['role']=='member'

def test_mfa_enrollment_requires_current_password(app,clients):
    alice,h,uid=clients['alice']
    assert call(alice,'/api/v1/auth/totp/setup',h,data={'password':'wrong'}).status_code==403
    r=call(alice,'/api/v1/auth/totp/setup',h,data={'password':'synthetic password for tests'});assert r.status_code==200,r.json
    secret=r.json['secret'];code=totp(secret)
    r=call(alice,'/api/v1/auth/totp/enable',h,data={'code':code});assert r.status_code==200 and len(r.json['recovery_codes'])==10
    assert call(alice,'/api/v1/auth/totp/verify',h,data={'code':code}).status_code==403

def test_device_approval_is_bound_and_grant_cannot_moderate(app,clients):
    public=app.test_client()
    start=public.post('/api/v1/oauth/device',json={'client_id':'grocyste-core','instance':'https://grocy.example.test'},base_url='https://community.test').json
    alice,h,_=clients['alice'];result=call(alice,'/api/v1/oauth/approve',h,data={'user_code':start['user_code'],'approve':True});assert result.status_code==200,result.json
    token=public.post('/api/v1/oauth/token',json={'client_id':'grocyste-core','grant_type':'urn:ietf:params:oauth:grant-type:device_code','device_code':start['device_code']},base_url='https://community.test').json
    assert 'access_token' in token,token
    bearer={'Authorization':'Bearer '+token['access_token']}
    assert public.get('/api/v1/contributions',headers=bearer,base_url='https://community.test').status_code==200
    assert public.get('/api/v1/moderation',headers=bearer,base_url='https://community.test').status_code==403
    result=public.post('/api/v1/oauth/token',json={'client_id':'grocyste-core','grant_type':'refresh_token','refresh_token':token['refresh_token']},base_url='https://community.test')
    assert result.status_code==200,result.json
    assert public.get('/api/v1/contributions',headers=bearer,base_url='https://community.test').status_code==401

def test_public_views_do_not_contain_account_secrets(app,clients):
    alice,_,uid=clients['alice'];r=alice.get('/api/v1/profiles/'+uid,base_url='https://community.test')
    assert r.status_code==200
    assert not any(k in str(r.json) for k in ('password','@example.test','totp','recovery'))
