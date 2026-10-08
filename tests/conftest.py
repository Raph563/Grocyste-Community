import base64,time,os,uuid
import pytest
from sqlalchemy import insert,select,update
from community.app import create_app
from community.cli import keys
from community import db
from community.security import password,digest,opaque,csrf

@pytest.fixture
def app(tmp_path):
    key=keys(tmp_path/'signing.key',tmp_path/'signing.pub')
    url='sqlite:///'+str(tmp_path/'community.db');pg=None;schema=None
    if os.environ.get('TEST_DATABASE_URL_FILE'):
        from pathlib import Path
        from sqlalchemy import create_engine,text
        from sqlalchemy.engine import make_url
        raw=Path(os.environ['TEST_DATABASE_URL_FILE']).read_text().strip();pg=create_engine(raw)
        schema='test_'+uuid.uuid4().hex
        with pg.begin() as conn:conn.execute(text('CREATE SCHEMA '+schema))
        url=make_url(raw).update_query_dict({'options':'-c search_path='+schema}).render_as_string(hide_password=False)
    application=create_app({'TESTING':True,'DATABASE_URL':url,
        'PUBLIC_ORIGIN':'https://community.test','STATE_DIR':str(tmp_path/'state'),
        'SEAL_KEY_FILE':str(tmp_path/'seal.key'),'DATA_PUBLIC_KEY_FILE':str(tmp_path/'signing.pub'),
        'SIGNUPS_OPEN':True,'DUMMY_PASSWORD':password('a different synthetic password')})
    application.test_signing_key=key
    yield application
    application.extensions['community'].db.dispose()
    if pg:
        from sqlalchemy import text
        with pg.begin() as conn:conn.execute(text('DROP SCHEMA '+schema+' CASCADE'))
        pg.dispose()

@pytest.fixture
def clients(app):
    s=app.extensions['community'];result={}
    with s.db.begin() as conn:
        for name,role in [('alice','member'),('bob','member'),('staff','admin')]:
            user_id=db.uid();sid=opaque()
            conn.execute(insert(db.users).values(id=user_id,email=name+'@example.test',name=name,name_key=name,password=password('synthetic password for tests'),role=role,status='active',created=time.time(),bio='',preferences={},recovery=[],totp_counter=-1))
            conn.execute(insert(db.sessions).values(hash=digest(sid),user_id=user_id,created=time.time(),touched=time.time(),expires=time.time()+3600,mfa=role=='admin'))
            client=app.test_client();client.set_cookie('grocyste_community',sid,domain='community.test')
            result[name]=(client,{'Origin':'https://community.test','X-CSRF-Token':csrf(s.secret,sid),'Idempotency-Key':db.uid()},user_id)
    return result

def call(client,path,headers,method='POST',data=None,key=None):
    return client.open(path,method=method,json={} if data is None else data,headers={**headers,'Idempotency-Key':key or db.uid()},base_url='https://community.test')
