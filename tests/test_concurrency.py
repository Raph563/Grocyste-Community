import threading,time
from concurrent.futures import ThreadPoolExecutor
import pytest
from sqlalchemy import select,insert,update
from community import db
from community.security import canonical,digest
from community.worker import publish_one,mail_one

def pg_only(app):
    if app.extensions['community'].db.dialect.name!='postgresql':pytest.skip('Qualification PostgreSQL nécessaire')

def test_same_idempotency_key_creates_one_entry_across_workers(app,clients):
    pg_only(app);_,headers,uid=clients['alice'];body={'kind':'product','content':{'name':'Produit concurrent synthétique','stock_unit':'pièce','rights_confirmed':True}}
    cookie=clients['alice'][0].get_cookie('grocyste_community',domain='community.test').value
    def create(_):
        c=app.test_client();c.set_cookie('grocyste_community',cookie,domain='community.test')
        return c.post('/api/v1/contributions',json=body,headers=headers,base_url='https://community.test')
    with ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(create,range(4)))
    assert {r.status_code for r in results}=={201}
    assert len({r.json['id'] for r in results})==1
    with app.extensions['community'].db.connect() as conn:assert len(conn.execute(select(db.entries).where(db.entries.c.owner_id==uid)).all())==1

def test_mail_claim_is_unique_and_publication_cannot_deadlock_editor(app,clients):
    pg_only(app);s=app.extensions['community'];alice,headers,uid=clients['alice'];now=time.time()
    with app.app_context(),s.db.begin() as conn:s.mail(conn,'alice@example.test','security',{'message':'Message synthétique'},'parallel-delivery')
    count=[];lock=threading.Lock()
    def sender(_):
        with app.app_context():
            def transport(msg):
                with lock:count.append(msg['Message-ID'])
            return mail_one(s,transport)
    with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(sender,range(4)))
    assert len(count)==1
    created=alice.post('/api/v1/contributions',json={'kind':'product','content':{'name':'Publication concurrente','stock_unit':'pièce','rights_confirmed':True}},headers=headers,base_url='https://community.test').json
    with s.db.begin() as conn:conn.execute(update(db.revisions).where(db.revisions.c.id==created['id']).values(state='approved',reviewed=now))
    def publish(_):
        with app.app_context():return publish_one(s,app.test_signing_key)
    with ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(publish,range(3)))
    with s.db.connect() as conn:assert conn.execute(select(db.entries.c.published).where(db.entries.c.id==created['id'])).scalar()==1
