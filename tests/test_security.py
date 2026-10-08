import base64,json,time
from io import BytesIO
import pytest
from PIL import Image
from sqlalchemy import select,update,insert
from community import db,content
from community.security import Error,canonical,digest,totp,totp_counter,safe_image
from community.worker import publish_one,mail_one
from conftest import call

def product():return {'kind':'product','content':{'name':'Produit synthétique','stock_unit':'g','purchase_unit':'g','rights_confirmed':True,'barcodes':['1234567890128']}}

def publish(app,clients):
    client,h,_=clients['alice'];r=call(client,'/api/v1/contributions',h,data=product());assert r.status_code==201,r.json
    entry_id=r.json['id'];r=call(client,'/api/v1/contributions/'+entry_id+'/submit',h,data={'revision':1});assert r.status_code==200,r.json
    staff,sh,_=clients['staff'];r=call(staff,'/api/v1/moderation/entries/'+entry_id+'/1',sh,data={'approve':True,'reason':'Source synthétique vérifiée'});assert r.status_code==200,r.json
    with app.app_context():assert publish_one(app.extensions['community'],app.test_signing_key)
    return entry_id

def test_anonymous_csrf_and_origin(app,clients):
    c=app.test_client();assert c.get('/api/v1/contributions',base_url='https://community.test').status_code==401
    alice,h,_=clients['alice']
    for bad in ({**h,'Origin':'https://evil.test'},{**h,'X-CSRF-Token':'forged'}):
        assert call(alice,'/api/v1/contributions',bad,data=product()).status_code==403

def test_draft_namespace_and_idempotency(app,clients):
    alice,h,_=clients['alice'];bob,bh,_=clients['bob'];key=db.uid()
    first=call(alice,'/api/v1/contributions',h,data=product(),key=key);assert first.status_code==201,first.json
    second=call(alice,'/api/v1/contributions',h,data=product(),key=key);assert second.json==first.json
    changed=product();changed['content']['name']='Autre'
    assert call(alice,'/api/v1/contributions',h,data=changed,key=key).status_code==409
    entry_id=first.json['id']
    assert bob.get('/api/v1/contributions/'+entry_id,base_url='https://community.test').status_code==404
    assert bob.get('/api/v1/entries/'+entry_id,base_url='https://community.test').status_code==404
    assert call(bob,'/api/v1/contributions/'+entry_id,bh,method='PUT',data={'revision':1,'content':product()['content']}).status_code==404

def test_moderation_staff_mfa_and_signature(app,clients):
    alice,h,_=clients['alice'];entry_id=publish(app,clients)
    result=alice.get('/api/v1/entries/'+entry_id,base_url='https://community.test').json['entry']
    app.test_signing_key.public_key().verify(base64.b64decode(result['signature']),canonical(result['record']).encode())
    assert result['sha256']==digest(canonical(result['record']))
    assert alice.get('/api/v1/moderation',base_url='https://community.test').status_code==403
    staff,sh,uid=clients['staff'];s=app.extensions['community']
    with s.db.begin() as conn:conn.execute(update(db.sessions).where(db.sessions.c.user_id==uid).values(mfa=False))
    assert staff.get('/api/v1/moderation',base_url='https://community.test').json['error']['code']=='mfa_required'

def test_permissions_revoked_and_user_roles_cannot_be_injected(app,clients):
    alice,h,uid=clients['alice'];s=app.extensions['community']
    b=product();b['role']='admin';assert call(alice,'/api/v1/contributions',h,data=b).status_code==400
    with s.db.begin() as conn:conn.execute(update(db.users).where(db.users.c.id==uid).values(status='suspended'))
    assert call(alice,'/api/v1/contributions',h,data=product()).status_code in (401,403)

def test_pack_missing_reference_and_empty_id(app,clients):
    alice,h,_=clients['alice'];b={'kind':'pack','content':{'name':'Pack test','items':[{'id':'','revision':1}],'rights_confirmed':True}}
    assert call(alice,'/api/v1/contributions',h,data=b).status_code==400
    b['content']['items'][0]['id']='p-unknown'
    r=call(alice,'/api/v1/contributions',h,data=b);assert r.status_code==201
    assert call(alice,'/api/v1/contributions/'+r.json['id']+'/submit',h,data={'revision':1}).status_code==409

def test_media_decoding_metadata_and_cross_account_access(app,clients):
    image=Image.new('RGB',(24,24),'red');out=BytesIO();image.save(out,'PNG',pnginfo=None)
    encoded,w,h=safe_image(out.getvalue());assert (w,h)==(24,24)
    with Image.open(BytesIO(encoded)) as decoded:assert not decoded.getexif()
    alice,headers,_=clients['alice'];bob,bh,_=clients['bob'];body={'data':base64.b64encode(out.getvalue()).decode(),'author':'Auteur synthétique','license':'CC-BY-SA-4.0','rights_confirmed':True}
    result=call(alice,'/api/v1/media',headers,data=body);assert result.status_code==200,result.json
    path='/media/'+result.json['id']+'.jpg'
    assert alice.get(path,base_url='https://community.test').status_code==200
    assert bob.get(path,base_url='https://community.test').status_code==404
    body['data']=base64.b64encode(b'<svg onload="alert(1)"></svg>').decode()
    assert call(alice,'/api/v1/media',headers,data=body).status_code==400

def test_comments_hidden_until_review_and_votes_unique(app,clients):
    entry_id=publish(app,clients);alice,h,_=clients['alice'];staff,sh,_=clients['staff']
    result=call(alice,'/api/v1/entries/'+entry_id+'/comments',h,data={'text':'<img src=x onerror=alert(1)> commentaire'});assert result.status_code==202
    assert alice.get('/api/v1/entries/'+entry_id+'/comments',base_url='https://community.test').json['comments']==[]
    assert call(staff,'/api/v1/moderation/comments/'+result.json['id'],sh,data={'approve':True,'reason':'Texte affiché sans HTML'}).status_code==200
    assert len(alice.get('/api/v1/entries/'+entry_id+'/comments',base_url='https://community.test').json['comments'])==1
    for v in (3,5):assert call(alice,'/api/v1/entries/'+entry_id+'/rating',h,method='PUT',data={'value':v}).status_code==200
    rating=alice.get('/api/v1/entries/'+entry_id,base_url='https://community.test').json['rating'];assert rating=={'average':5.0,'count':1}

def test_json_urls_private_fields_and_limits(app,clients):
    alice,h,_=clients['alice']
    for key,value in [('source','http://127.0.0.1:9283'),('source','https://evil.test@127.0.0.1'),('stock',{'amount':9}),('grocy_api_key','secret')]:
        b=product();b['content'][key]=value;assert call(alice,'/api/v1/contributions',h,data=b).status_code==400
    for value in (-1,float('inf')):
        b=product();b['content']['conversions']=[{'from':'g','to':'kg','factor':value,'proven':True,'source':'Mesure'}]
        assert call(alice,'/api/v1/contributions',h,data=b).status_code==400
    assert alice.post('/api/v1/contributions',data='{',headers={**h,'Content-Type':'application/json'},base_url='https://community.test').status_code==400

def test_totp_replay_protection():
    secret='JBSWY3DPEHPK3PXP';at=1234567890;code=totp(secret,at);counter=totp_counter(secret,code,-1,at)
    assert counter==int(at//30);assert totp_counter(secret,code,counter,at) is None

def test_mail_claims_and_interruption_without_blind_retry(app):
    s=app.extensions['community'];messages=[]
    with app.app_context():
        with s.db.begin() as conn:s.mail(conn,'synthetic@example.test','notification',{'message':'Test'},'fixed');s.mail(conn,'synthetic@example.test','notification',{'message':'Test'},'fixed')
        assert mail_one(s,lambda msg:messages.append(msg));assert not mail_one(s,lambda msg:messages.append(msg));assert len(messages)==1
        with s.db.begin() as conn:
            s.mail(conn,'synthetic@example.test','notification',{'message':'Interrupted'},'interrupted')
            conn.execute(update(db.outbox).where(db.outbox.c.state=='pending').values(state='sending',claimed=time.time()-400))
        assert not mail_one(s,lambda msg:messages.append(msg))
        with s.db.connect() as conn:assert conn.execute(select(db.outbox.c.state).where(db.outbox.c.id==digest('notification:interrupted'))).scalar()=='uncertain'
