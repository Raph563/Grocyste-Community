"""Durable publication and SMTP workers. Ambiguous deliveries are not replayed."""
import argparse, base64, json, os, smtplib, ssl, time
from email.message import EmailMessage
from pathlib import Path
from sqlalchemy import select,update,and_,or_
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from . import db,content
from .app import create_app
from .security import Error,digest

def publish_one(s,key):
    with s.db.begin() as conn:
        candidate=conn.execute(select(db.revisions.c.id,db.revisions.c.revision).where(db.revisions.c.state=='approved').order_by(db.revisions.c.reviewed).limit(1)).mappings().first()
        if not candidate:return False
        # Take the same entry lock as editors before locking its revision.
        s.lock(conn,'entry:'+candidate['id'])
        revision=conn.execute(select(db.revisions).where(and_(db.revisions.c.id==candidate['id'],db.revisions.c.revision==candidate['revision'],db.revisions.c.state=='approved')).with_for_update()).mappings().first()
        if not revision:return False
        entry=db.row(conn,db.entries,db.entries.c.id==revision['id'])
        try:
            if entry['withdrawn'] or entry['latest']!=revision['revision']:raise Error('Publication dépassée ou fiche retirée')
            content.graph(conn,entry,revision)
            data=dict(revision['content']);credits=[]
            for image_id in data.get('images',[]):
                image=db.row(conn,db.media,db.media.c.id==image_id)
                if not image or (image['owner_id']!=entry['owner_id'] and not image['public']):raise Error('Droits de l’image indisponibles')
                path=(s.data/image['path']).resolve()
                if not path.is_relative_to(s.data.resolve()) or path.is_symlink() or digest(path.read_bytes())!=image_id:raise Error('Image altérée')
                credits.append({'id':image_id,**image['rights']})
                conn.execute(update(db.media).where(db.media.c.id==image_id).values(public=True))
            data['image_credits']=credits
            revision=dict(revision,content=data)
            sha,signature=content.sign(entry,revision,key)
            conn.execute(update(db.revisions).where(and_(db.revisions.c.id==entry['id'],db.revisions.c.revision==revision['revision'])).values(state='published',content=data,digest=sha,signature=signature))
            conn.execute(update(db.entries).where(db.entries.c.id==entry['id']).values(published=revision['revision']))
            if entry['owner_id']:
                s.notify(conn,entry['owner_id'],'moderation','Contribution publiée : '+data['name'],entry['id'])
                targets=conn.execute(select(db.subscriptions.c.user_id).where(or_(db.subscriptions.c.target==entry['id'],db.subscriptions.c.target=='profile:'+entry['owner_id']))).scalars().all()
                for target in set(targets):
                    if target!=entry['owner_id']:s.notify(conn,target,'publication','Nouvelle publication : '+data['name'],entry['id'])
            s.audit(conn,'publication.signed',entry['id'],{'revision':revision['revision'],'sha256':sha})
        except (Error,OSError) as exc:
            conn.execute(update(db.revisions).where(and_(db.revisions.c.id==revision['id'],db.revisions.c.revision==revision['revision'])).values(state='rejected',reason=str(exc) if isinstance(exc,Error) else 'Média indisponible'))
            if entry['owner_id']:s.notify(conn,entry['owner_id'],'moderation','Publication interrompue ; revoir la contribution',entry['id'])
        return True

def make_message(s,payload,job_id):
    p=payload['params'];kind=payload['kind']
    subjects={'verify':'Valider votre inscription Grocyste','reset':'Réinitialiser votre mot de passe Grocyste',
              'email-change':'Valider votre nouvelle adresse Grocyste','security':'Sécurité de votre compte Grocyste',
              'notification':'Une nouvelle notification Grocyste'}
    if kind in ('verify','reset','email-change'):
        page='reset' if kind=='reset' else 'verify'
        suffix='&kind=email-change' if kind=='email-change' else ''
        body='Bonjour,\n\n'+subjects[kind]+'.\nOuvrez ce lien puis confirmez l’action sur la page :\n'+s.origin+'/'+page+'#token='+p['token']+suffix+'\n\nCe lien est temporaire et utilisable une seule fois. Si vous n’avez rien demandé, ignorez cet email.'
    else:
        body=p['message']+'\n\n'+s.origin+('/entry/'+p['entry_id'] if p.get('entry_id') else '/account')
    msg=EmailMessage();msg['From']='Grocyste <'+s.config['SENDER']+'>';msg['To']=payload['to'];msg['Subject']=subjects[kind]
    msg['Message-ID']='<'+job_id+'@banane.fun>';msg['Auto-Submitted']='auto-generated';msg.set_content(body+'\n\nGrocyste Communauté — '+s.origin+'\n')
    return msg

def mail_one(s,transport=None):
    now=time.time()
    with s.db.begin() as conn:
        # A crashed sender could have handed the message to SMTP before its DB commit.
        conn.execute(update(db.outbox).where(and_(db.outbox.c.state=='sending',db.outbox.c.claimed<now-300)).values(state='uncertain',error='sender_interrupted'))
        job=conn.execute(select(db.outbox).where(and_(db.outbox.c.state=='pending',db.outbox.c.next_attempt<=now)).order_by(db.outbox.c.next_attempt).with_for_update(skip_locked=True).limit(1)).mappings().first()
        if not job:return False
        conn.execute(update(db.outbox).where(db.outbox.c.id==job['id']).values(state='sending',claimed=now,attempts=job['attempts']+1))
    data=s.vault.open(job['payload']);msg=make_message(s,data,job['id'])
    state='sent';error=None;phase='connect'
    try:
        if transport:transport(msg)
        else:
            login=json.loads(Path(s.config['SMTP_LOGIN_FILE']).read_text())
            with smtplib.SMTP(s.config['SMTP_HOST'],s.config['SMTP_PORT'],timeout=30) as smtp:
                smtp.ehlo();smtp.starttls(context=ssl.create_default_context());smtp.ehlo()
                smtp.login(login['username'],login['password']);phase='data'
                refused=smtp.send_message(msg,from_addr=s.config['SENDER'],to_addrs=[data['to']])
                if refused:raise smtplib.SMTPRecipientsRefused(refused)
    except (smtplib.SMTPRecipientsRefused,smtplib.SMTPSenderRefused,smtplib.SMTPAuthenticationError,smtplib.SMTPDataError) as exc:
        code=getattr(exc,'smtp_code',550);error=type(exc).__name__
        state='pending' if 400<=code<500 and job['attempts']<4 else 'failed'
    except (OSError,smtplib.SMTPException) as exc:
        error=type(exc).__name__;state='uncertain' if phase=='data' else ('pending' if job['attempts']<4 else 'failed')
    with s.db.begin() as conn:
        conn.execute(update(db.outbox).where(and_(db.outbox.c.id==job['id'],db.outbox.c.state=='sending')).values(state=state,error=error,sent=time.time() if state=='sent' else None,next_attempt=time.time()+min(3600,30*(2**job['attempts']))))
    return True

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--once',action='store_true');args=parser.parse_args()
    app=create_app();s=app.extensions['community'];key=Ed25519PrivateKey.from_private_bytes(base64.b64decode(Path(os.environ['DATA_SIGNING_KEY_FILE']).read_text().strip()))
    with app.app_context():
        while True:
            worked=publish_one(s,key)
            worked=mail_one(s) or worked
            if args.once:return
            if not worked:time.sleep(2)

if __name__=='__main__':main()
