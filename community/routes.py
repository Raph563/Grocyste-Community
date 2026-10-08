"""Public catalogue, owner-scoped drafts and staff-reviewed community actions."""
import json, os, re, time
from pathlib import Path
from flask import g, request, jsonify, send_file
from sqlalchemy import select, insert, update, delete, and_, or_, func
from . import db, content
from .security import Error, text, identifier, integer, digest, safe_image, canonical

def register(app,s):
    def published(conn,entry_id,revision=None):
        identifier(entry_id)
        entry=db.row(conn,db.entries,db.entries.c.id==entry_id)
        if not entry or entry['withdrawn'] or entry['published'] is None:raise Error('Fiche indisponible',404)
        rev=db.row(conn,db.revisions,and_(db.revisions.c.id==entry_id,db.revisions.c.revision==(revision or entry['published']),db.revisions.c.state=='published'))
        if not rev:raise Error('Version indisponible',404)
        return entry,rev

    def owned(conn,entry_id):
        identifier(entry_id);entry=db.row(conn,db.entries,db.entries.c.id==entry_id)
        if not entry or entry['owner_id']!=g.user['id']:raise Error('Contribution indisponible',404)
        return entry

    def authorize_media(conn,data):
        for media_id in data.get('images',[]):
            image=db.row(conn,db.media,db.media.c.id==media_id)
            if not image or (image['owner_id']!=g.user['id'] and not image['public']):raise Error('Image inaccessible',403)

    def pageable():
        try:page=int(request.args.get('page','1'));size=int(request.args.get('limit','48'))
        except ValueError:raise Error('Pagination invalide')
        return integer(page,1,10000),integer(size,1,100)

    @app.get('/api/v1/catalog')
    def catalogue():
        page,size=pageable();kind=request.args.get('kind','');language=request.args.get('language','')
        query=text(request.args.get('q',''),300);origin=request.args.get('origin','')
        if kind and kind not in ('product','recipe','pack'):raise Error('Type inconnu')
        if language and language not in ('fr','en'):raise Error('Langue inconnue')
        if origin and origin not in ('shared-facts','wikibooks','community'):raise Error('Collection inconnue')
        statement=select(db.entries,db.revisions.c.revision,db.revisions.c.content,db.revisions.c.created.label('revision_created'),db.revisions.c.state,db.users.c.name.label('author')).join(db.revisions,and_(db.entries.c.id==db.revisions.c.id,db.entries.c.published==db.revisions.c.revision)).outerjoin(db.users,db.entries.c.owner_id==db.users.c.id).where(and_(db.entries.c.withdrawn==False,db.revisions.c.state=='published'))
        if kind:statement=statement.where(db.entries.c.kind==kind)
        if language:statement=statement.where(db.revisions.c.language==language)
        if origin:statement=statement.where(db.revisions.c.content['origin'].as_string()==origin)
        if request.args.get('favorites')=='1':
            if not g.user or g.user['status']!='active':raise Error('Connexion requise',401)
            statement=statement.where(db.entries.c.id.in_(select(db.favorites.c.entry_id).where(db.favorites.c.user_id==g.user['id'])))
        for word in content.normalized(query).split()[:12]:statement=statement.where(db.revisions.c.search.contains(word,autoescape=True))
        with s.db.connect() as conn:
            count=conn.execute(select(func.count()).select_from(statement.subquery())).scalar()
            values=conn.execute(statement.order_by(db.revisions.c.name,db.entries.c.id).offset((page-1)*size).limit(size)).mappings().all()
        return jsonify(ok=True,total=count,page=page,limit=size,entries=[content.summary(v,{**dict(v),'created':v['revision_created']},v['author']) for v in values])

    @app.get('/api/v1/stats')
    def stats():
        with s.db.connect() as conn:
            values=conn.execute(select(db.entries.c.kind,func.count()).where(and_(db.entries.c.published.is_not(None),db.entries.c.withdrawn==False)).group_by(db.entries.c.kind)).all()
        return jsonify(ok=True,counts=dict(values))

    @app.get('/api/v1/entries/<entry_id>')
    def detail(entry_id):
        with s.db.connect() as conn:
            entry,revision=published(conn,entry_id)
            author=db.row(conn,db.users,db.users.c.id==entry['owner_id']) if entry['owner_id'] else None
            versions=conn.execute(select(db.revisions.c.revision,db.revisions.c.created).where(and_(db.revisions.c.id==entry_id,db.revisions.c.state=='published')).order_by(db.revisions.c.revision.desc())).mappings().all()
            rating=conn.execute(select(func.avg(db.ratings.c.value),func.count()).where(db.ratings.c.entry_id==entry_id)).first()
            images=conn.execute(select(db.media.c.id,db.media.c.rights,db.media.c.width,db.media.c.height).where(and_(db.media.c.id.in_(revision['content'].get('images',[])),db.media.c.public==True))).mappings().all()
        return jsonify(ok=True,entry=content.envelope(entry,revision,s.public_key),author=s.public_user(author) if author else None,versions=[dict(v) for v in versions],rating={'average':float(rating[0]) if rating[0] is not None else None,'count':rating[1]},images=[dict(v) for v in images])

    @app.get('/api/v1/entries/<entry_id>/revisions/<int:version>')
    def version(entry_id,version):
        with s.db.connect() as conn:entry,revision=published(conn,entry_id,integer(version))
        return jsonify(ok=True,entry=content.envelope(entry,revision,s.public_key))

    @app.get('/api/v1/entries/<entry_id>/revisions/<int:version>/download')
    def download(entry_id,version):
        with s.db.connect() as conn:
            entry,revision=published(conn,entry_id,integer(version));ordered=content.graph(conn,entry,revision)
            records=[content.envelope(e,r,s.public_key) for e,r in ordered]
        response=jsonify(schema='grocyste-pack-v1',root={'id':entry_id,'revision':version},entries=records)
        response.headers['Content-Disposition']=f'attachment; filename="{entry_id}-v{version}.grocyste.json"'
        return response

    @app.get('/api/v1/profiles/<user_id>')
    def public_profile(user_id):
        with s.db.connect() as conn:
            user=db.row(conn,db.users,db.users.c.id==user_id)
            if not user or not (user['status']=='active' or user['status']=='invited' and user['name_key']=='raph563'):raise Error('Profil indisponible',404)
            entries=conn.execute(select(db.entries,db.revisions.c.revision,db.revisions.c.content,db.revisions.c.created.label('revision_created'),db.revisions.c.state).join(db.revisions,and_(db.entries.c.id==db.revisions.c.id,db.entries.c.published==db.revisions.c.revision)).where(and_(db.entries.c.owner_id==user_id,db.entries.c.withdrawn==False)).order_by(db.revisions.c.name).limit(1000)).mappings().all()
        return jsonify(ok=True,profile=s.public_user(user),entries=[content.summary(v,{**dict(v),'created':v['revision_created']},user['name']) for v in entries])

    @app.get('/api/v1/contributions')
    @s.actor()
    def contributions():
        with s.db.connect() as conn:
            values=conn.execute(select(db.entries,db.revisions.c.revision,db.revisions.c.content,db.revisions.c.created.label('revision_created'),db.revisions.c.state,db.revisions.c.reason).join(db.revisions,and_(db.entries.c.id==db.revisions.c.id,db.entries.c.latest==db.revisions.c.revision)).where(db.entries.c.owner_id==g.user['id']).order_by(db.revisions.c.created.desc()).limit(1000)).mappings().all()
        return jsonify(ok=True,entries=[{**content.summary(v,{**dict(v),'created':v['revision_created']}),'reason':v['reason']} for v in values])

    @app.get('/api/v1/contributions/<entry_id>')
    @s.actor()
    def contribution(entry_id):
        with s.db.connect() as conn:
            entry=owned(conn,entry_id);revision=db.row(conn,db.revisions,and_(db.revisions.c.id==entry_id,db.revisions.c.revision==entry['latest']))
        return jsonify(ok=True,entry={'id':entry_id,'kind':entry['kind'],'revision':revision['revision'],'state':revision['state'],'content':revision['content'],'reason':revision['reason']})

    @app.post('/api/v1/contributions')
    @s.actor()
    @s.mutate
    def create(conn,b):
        if set(b)!={'kind','content'}:raise Error('Type et contenu requis')
        s.rate('contribute',20,3600,identity=g.user['id'])
        data=content.validate(b['kind'],b['content']);authorize_media(conn,data)
        entry_id={'product':'p','recipe':'r','pack':'k'}[b['kind']]+'-'+db.uid()
        conn.execute(insert(db.entries).values(id=entry_id,kind=b['kind'],owner_id=g.user['id'],published=None,latest=1,created=time.time(),withdrawn=False))
        conn.execute(insert(db.revisions).values(id=entry_id,revision=1,author_id=g.user['id'],state='draft',content=data,name=data['name'],language=data['language'],search=content.search_text(data),created=time.time()))
        s.audit(conn,'contribution.created',entry_id)
        return {'ok':True,'id':entry_id,'revision':1,'state':'draft'},201

    @app.put('/api/v1/contributions/<entry_id>')
    @s.actor()
    @s.mutate
    def edit(conn,b,entry_id):
        if set(b)!={'revision','content'}:raise Error('Révision et contenu requis')
        s.lock(conn,'entry:'+entry_id);entry=owned(conn,entry_id)
        if entry['latest']!=integer(b['revision']):raise Error('Une nouvelle révision existe ; recharger la fiche',409)
        previous=db.row(conn,db.revisions,and_(db.revisions.c.id==entry_id,db.revisions.c.revision==entry['latest']))
        if previous['state']=='approved':raise Error('Publication en cours ; attendre sa fin',409)
        data=content.validate(entry['kind'],b['content']);authorize_media(conn,data)
        # Attribution inherited from the reviewed original cannot be silently stripped.
        for key in ('origin','source_text','source_revision','contributors','modifications','unresolved_markup'):
            if key in previous['content']:data[key]=previous['content'][key]
        if previous['content'].get('license')=='CC-BY-SA-4.0' and data['license']!='CC-BY-SA-4.0':raise Error('Cette adaptation conserve la licence CC BY-SA 4.0')
        if previous['state'] in ('draft','pending'):
            conn.execute(update(db.revisions).where(and_(db.revisions.c.id==entry_id,db.revisions.c.revision==entry['latest'])).values(state='rejected',reason='Remplacée par une nouvelle révision'))
        revision=entry['latest']+1
        conn.execute(insert(db.revisions).values(id=entry_id,revision=revision,author_id=g.user['id'],state='draft',content=data,name=data['name'],language=data['language'],search=content.search_text(data),created=time.time()))
        conn.execute(update(db.entries).where(db.entries.c.id==entry_id).values(latest=revision));s.audit(conn,'contribution.updated',entry_id,{'revision':revision})
        return {'ok':True,'id':entry_id,'revision':revision,'state':'draft'}

    @app.post('/api/v1/contributions/<entry_id>/submit')
    @s.actor()
    @s.mutate
    def submit(conn,b,entry_id):
        if set(b)!={'revision'}:raise Error('Révision requise')
        s.lock(conn,'entry:'+entry_id);entry=owned(conn,entry_id)
        if entry['latest']!=integer(b['revision']):raise Error('Révision dépassée',409)
        rev=db.row(conn,db.revisions,and_(db.revisions.c.id==entry_id,db.revisions.c.revision==entry['latest']))
        if rev['state'] not in ('draft','rejected'):raise Error('Contribution déjà soumise',409)
        content.graph(conn,entry,rev);authorize_media(conn,rev['content'])
        if rev['content'].get('rights_confirmed') is not True:raise Error('Confirmer les droits de partage')
        conn.execute(update(db.revisions).where(and_(db.revisions.c.id==entry_id,db.revisions.c.revision==rev['revision'])).values(state='pending',reason=None))
        s.audit(conn,'contribution.submitted',entry_id,{'revision':rev['revision']})
        return {'ok':True,'state':'pending'}

    @app.post('/api/v1/media')
    @s.actor()
    def upload():
        s.rate('image',30,3600,identity=g.user['id'])
        if not request.is_json:raise Error('Image encodée requise')
        b=s.body({'data','author','license','rights_confirmed'},{'data','author','license','rights_confirmed'})
        if b['rights_confirmed'] is not True or b['license']!='CC-BY-SA-4.0':raise Error('Confirmer les droits et la licence de l’image')
        import base64
        try:raw=base64.b64decode(text(b['data'],14_000_000,1),validate=True)
        except ValueError:raise Error('Image invalide')
        encoded,width,height=safe_image(raw);image_id=digest(encoded);path=s.data/'media'/image_id[:2]/(image_id+'.jpg')
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with s.db.begin() as conn:
            existing=db.row(conn,db.media,db.media.c.id==image_id)
            if existing:
                if existing['owner_id']!=g.user['id'] and not existing['public']:raise Error('Image inaccessible',409)
                return jsonify(ok=True,id=image_id,width=existing['width'],height=existing['height'])
            temporary=path.with_suffix('.'+db.uid()+'.tmp')
            with open(temporary,'xb') as out:out.write(encoded);out.flush();os.fsync(out.fileno())
            os.replace(temporary,path);os.chmod(path,0o600)
            conn.execute(insert(db.media).values(id=image_id,owner_id=g.user['id'],path=str(path.relative_to(s.data)),size=len(encoded),width=width,height=height,rights={'author':text(b['author'],300,1),'license':'CC-BY-SA-4.0'},public=False,created=time.time()))
        return jsonify(ok=True,id=image_id,width=width,height=height)

    @app.get('/media/<image_id>.jpg')
    def image(image_id):
        if not re.fullmatch(r'[a-f0-9]{64}',image_id):raise Error('Image inconnue',404)
        with s.db.connect() as conn:value=db.row(conn,db.media,db.media.c.id==image_id)
        if not value or (not value['public'] and (not g.user or g.user['id']!=value['owner_id'] and not (g.user['role'] in ('admin','moderator') and g.session and g.session['mfa']))):raise Error('Image inconnue',404)
        path=(s.data/value['path']).resolve()
        if not path.is_relative_to(s.data.resolve()) or not path.is_file() or path.is_symlink():raise Error('Image inconnue',404)
        response=send_file(path,mimetype='image/jpeg',conditional=True)
        response.headers['Cache-Control']='public, max-age=86400' if value['public'] else 'private, no-store'
        return response

    @app.get('/api/v1/favorites')
    @s.actor()
    def favorites():
        with s.db.connect() as conn:values=conn.execute(select(db.favorites.c.entry_id).where(db.favorites.c.user_id==g.user['id'])).scalars().all()
        return jsonify(ok=True,ids=values)

    @app.put('/api/v1/entries/<entry_id>/favorite')
    @s.actor()
    @s.mutate
    def favorite(conn,b,entry_id):
        if set(b)!={'enabled'} or type(b['enabled']) is not bool:raise Error('Décision requise')
        published(conn,entry_id);s.lock(conn,'favorite:'+g.user['id']+entry_id)
        where=and_(db.favorites.c.user_id==g.user['id'],db.favorites.c.entry_id==entry_id)
        conn.execute(delete(db.favorites).where(where))
        if b['enabled']:conn.execute(insert(db.favorites).values(user_id=g.user['id'],entry_id=entry_id,created=time.time()))
        return {'ok':True,'enabled':b['enabled']}

    @app.put('/api/v1/subscriptions/<target>')
    @s.actor()
    @s.mutate
    def subscribe(conn,b,target):
        if set(b)!={'enabled'} or type(b['enabled']) is not bool:raise Error('Décision requise')
        if target.startswith('profile:'):
            user=db.row(conn,db.users,db.users.c.id==target[8:])
            if not user or user['status']!='active':raise Error('Profil inconnu',404)
        else:published(conn,target)
        where=and_(db.subscriptions.c.user_id==g.user['id'],db.subscriptions.c.target==target)
        s.lock(conn,'subscription:'+g.user['id']+target);conn.execute(delete(db.subscriptions).where(where))
        if b['enabled']:conn.execute(insert(db.subscriptions).values(user_id=g.user['id'],target=target,created=time.time()))
        return {'ok':True,'enabled':b['enabled']}

    @app.get('/api/v1/subscriptions')
    @s.actor()
    def subscriptions():
        with s.db.connect() as conn:values=conn.execute(select(db.subscriptions.c.target).where(db.subscriptions.c.user_id==g.user['id'])).scalars().all()
        return jsonify(ok=True,targets=values)

    @app.put('/api/v1/entries/<entry_id>/rating')
    @s.actor()
    @s.mutate
    def rating(conn,b,entry_id):
        if set(b)!={'value'}:raise Error('Note requise')
        value=integer(b['value'],1,5);published(conn,entry_id);s.lock(conn,'rating:'+g.user['id']+entry_id)
        conn.execute(delete(db.ratings).where(and_(db.ratings.c.user_id==g.user['id'],db.ratings.c.entry_id==entry_id)))
        conn.execute(insert(db.ratings).values(user_id=g.user['id'],entry_id=entry_id,value=value,created=time.time()))
        return {'ok':True,'value':value}

    @app.get('/api/v1/entries/<entry_id>/comments')
    def comments(entry_id):
        page,size=pageable()
        with s.db.connect() as conn:
            published(conn,entry_id)
            values=conn.execute(select(db.comments.c.id,db.comments.c.text,db.comments.c.created,db.users.c.name.label('author'),db.users.c.id.label('author_id')).join(db.users,db.comments.c.user_id==db.users.c.id).where(and_(db.comments.c.entry_id==entry_id,db.comments.c.state=='published')).order_by(db.comments.c.created).offset((page-1)*size).limit(size)).mappings().all()
        return jsonify(ok=True,comments=[dict(v) for v in values])

    @app.post('/api/v1/entries/<entry_id>/comments')
    @s.actor()
    @s.mutate
    def comment(conn,b,entry_id):
        if set(b)!={'text'}:raise Error('Commentaire requis')
        s.rate('comment',20,3600,identity=g.user['id']);published(conn,entry_id);comment_id=db.uid()
        conn.execute(insert(db.comments).values(id=comment_id,entry_id=entry_id,user_id=g.user['id'],text=text(b['text'],4000,1),state='pending',created=time.time()))
        return {'ok':True,'id':comment_id,'state':'pending'},202

    @app.post('/api/v1/entries/<entry_id>/reports')
    @s.actor()
    @s.mutate
    def report(conn,b,entry_id):
        if set(b)!={'reason'}:raise Error('Motif requis')
        s.rate('report',10,3600,identity=g.user['id']);published(conn,entry_id);report_id=db.uid()
        conn.execute(insert(db.reports).values(id=report_id,user_id=g.user['id'],entry_id=entry_id,reason=text(b['reason'],4000,1),state='open',created=time.time()))
        return {'ok':True,'id':report_id,'state':'open'},202

    @app.get('/api/v1/notifications')
    @s.actor()
    def notifications():
        with s.db.connect() as conn:values=conn.execute(select(db.notifications).where(db.notifications.c.user_id==g.user['id']).order_by(db.notifications.c.created.desc()).limit(100)).mappings().all()
        return jsonify(ok=True,notifications=[dict(v) for v in values])

    @app.put('/api/v1/notifications/<notification_id>')
    @s.actor()
    @s.mutate
    def read_notification(conn,b,notification_id):
        if b!={'read':True}:raise Error('Confirmation requise')
        conn.execute(update(db.notifications).where(and_(db.notifications.c.user_id==g.user['id'],db.notifications.c.id==notification_id)).values(read=True))
        return {'ok':True}

    @app.get('/api/v1/moderation')
    @s.actor(roles=('admin','moderator'),grants=False)
    def moderation():
        with s.db.connect() as conn:
            pending=conn.execute(select(db.entries.c.kind,db.revisions).join(db.entries,db.entries.c.id==db.revisions.c.id).where(db.revisions.c.state.in_(['pending','approved'])).order_by(db.revisions.c.created).limit(100)).mappings().all()
            own_comments=conn.execute(select(db.comments).where(db.comments.c.state=='pending').order_by(db.comments.c.created).limit(100)).mappings().all()
            flagged=conn.execute(select(db.reports).where(db.reports.c.state=='open').order_by(db.reports.c.created).limit(100)).mappings().all()
        return jsonify(ok=True,contributions=[dict(v) for v in pending],comments=[dict(v) for v in own_comments],reports=[dict(v) for v in flagged])

    @app.post('/api/v1/moderation/entries/<entry_id>/<int:version>')
    @s.actor(roles=('admin','moderator'),grants=False)
    @s.mutate
    def decide(conn,b,entry_id,version):
        if set(b)!={'approve','reason'} or type(b['approve']) is not bool:raise Error('Décision et motif requis')
        reason=text(b['reason'],2000,1);s.lock(conn,'entry:'+entry_id)
        entry=db.row(conn,db.entries,db.entries.c.id==identifier(entry_id));rev=db.row(conn,db.revisions,and_(db.revisions.c.id==entry_id,db.revisions.c.revision==integer(version)))
        if not entry or not rev or entry['latest']!=version or rev['state']!='pending':raise Error('Contribution dépassée ou déjà traitée',409)
        if b['approve']:content.graph(conn,entry,rev)
        state='approved' if b['approve'] else 'rejected'
        conn.execute(update(db.revisions).where(and_(db.revisions.c.id==entry_id,db.revisions.c.revision==version)).values(state=state,reason=reason,reviewed=time.time()))
        s.audit(conn,'moderation.'+state,entry_id,{'revision':version,'reason':reason})
        if not b['approve']:s.notify(conn,entry['owner_id'],'moderation','Contribution refusée : '+reason,entry_id)
        return {'ok':True,'state':state}

    @app.post('/api/v1/moderation/comments/<comment_id>')
    @s.actor(roles=('admin','moderator'),grants=False)
    @s.mutate
    def decide_comment(conn,b,comment_id):
        if set(b)!={'approve','reason'} or type(b['approve']) is not bool:raise Error('Décision et motif requis')
        reason=text(b['reason'],2000,1);value=db.row(conn,db.comments,db.comments.c.id==comment_id)
        if not value or value['state']!='pending':raise Error('Commentaire indisponible',409)
        state='published' if b['approve'] else 'rejected'
        conn.execute(update(db.comments).where(db.comments.c.id==comment_id).values(state=state,reason=reason))
        s.notify(conn,value['user_id'],'comment','Commentaire '+('publié' if b['approve'] else 'refusé : '+reason),value['entry_id'])
        if b['approve']:
            subscribers=conn.execute(select(db.subscriptions.c.user_id).where(db.subscriptions.c.target==value['entry_id'])).scalars().all()
            for target in subscribers:
                if target!=value['user_id']:s.notify(conn,target,'comment','Nouveau commentaire sur une fiche suivie',value['entry_id'])
        s.audit(conn,'comment.'+state,comment_id,{'reason':reason});return {'ok':True,'state':state}

    @app.post('/api/v1/moderation/reports/<report_id>')
    @s.actor(roles=('admin','moderator'),grants=False)
    @s.mutate
    def resolve_report(conn,b,report_id):
        if set(b)!={'decision'}:raise Error('Décision requise')
        value=db.row(conn,db.reports,db.reports.c.id==report_id)
        if not value or value['state']!='open':raise Error('Signalement indisponible',409)
        decision=text(b['decision'],2000,1)
        conn.execute(update(db.reports).where(db.reports.c.id==report_id).values(state='closed',decision=decision))
        s.notify(conn,value['user_id'],'report','Signalement traité : '+decision,value['entry_id']);s.audit(conn,'report.closed',report_id,{'decision':decision})
        return {'ok':True}

    @app.post('/api/v1/moderation/entries/<entry_id>/withdraw')
    @s.actor(roles=('admin','moderator'),grants=False)
    @s.mutate
    def withdraw(conn,b,entry_id):
        if set(b)!={'reason'}:raise Error('Motif requis')
        reason=text(b['reason'],2000,1);s.lock(conn,'entry:'+entry_id);entry,rev=published(conn,entry_id)
        conn.execute(update(db.entries).where(db.entries.c.id==entry_id).values(withdrawn=True))
        s.audit(conn,'entry.withdrawn',entry_id,{'reason':reason})
        if entry['owner_id']:s.notify(conn,entry['owner_id'],'moderation','Fiche retirée : '+reason,entry_id)
        return {'ok':True}

    @app.get('/api/v1/admin/users')
    @s.actor(roles=('admin',),grants=False)
    def users():
        with s.db.connect() as conn:values=conn.execute(select(db.users.c.id,db.users.c.name,db.users.c.email,db.users.c.role,db.users.c.status).order_by(db.users.c.created.desc()).limit(500)).mappings().all()
        return jsonify(ok=True,users=[dict(v) for v in values])

    @app.put('/api/v1/admin/users/<user_id>')
    @s.actor(roles=('admin',),grants=False)
    @s.mutate
    def manage_user(conn,b,user_id):
        if set(b)!={'role','status','reason'} or b['role'] not in ('member','moderator','admin') or b['status'] not in ('active','suspended'):raise Error('Réglages invalides')
        reason=text(b['reason'],2000,1);s.lock(conn,'staff-roles');user=db.row(conn,db.users,db.users.c.id==user_id)
        if not user or user['status'] not in ('active','suspended'):raise Error('Compte indisponible',404)
        if b['role']!='member' and not user['totp']:raise Error('Le compte doit configurer la double authentification avant sa promotion',409)
        if user['role']=='admin' and (b['role']!='admin' or b['status']!='active'):
            count=conn.execute(select(func.count()).select_from(db.users).where(and_(db.users.c.role=='admin',db.users.c.status=='active'))).scalar()
            if count<2:raise Error('Conserver un administrateur actif',409)
        conn.execute(update(db.users).where(db.users.c.id==user_id).values(role=b['role'],status=b['status']))
        from .accounts import revoke_all
        revoke_all(conn,user_id);s.audit(conn,'account.managed',user_id,{'role':b['role'],'status':b['status'],'reason':reason})
        return {'ok':True}

    @app.get('/api/v1/admin/audit')
    @s.actor(roles=('admin',),grants=False)
    def audit():
        with s.db.connect() as conn:values=conn.execute(select(db.audit).order_by(db.audit.c.created.desc()).limit(200)).mappings().all()
        return jsonify(ok=True,events=[dict(v) for v in values])

    @app.get('/api/v1/admin/mail')
    @s.actor(roles=('admin',),grants=False)
    def mail_status():
        with s.db.connect() as conn:values=conn.execute(select(db.outbox.c.id,db.outbox.c.state,db.outbox.c.attempts,db.outbox.c.next_attempt,db.outbox.c.sent,db.outbox.c.error).order_by(db.outbox.c.next_attempt.desc()).limit(100)).mappings().all()
        return jsonify(ok=True,jobs=[dict(v) for v in values])
