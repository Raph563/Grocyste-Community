"""Operator-only schema, seed, invitation and backup commands."""
import argparse,base64,json,os,time
from pathlib import Path
from sqlalchemy import select,insert,update,and_
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from . import db,content
from .security import canonical,digest,opaque,secret_file,normalized

def keys(private,public):
    private=Path(private);public=Path(public);private.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if not private.exists():
        if public.exists():raise RuntimeError('Clé privée absente : restaurer la clé avant toute écriture')
        key=Ed25519PrivateKey.generate();raw=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        fd=os.open(private,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as out:out.write(base64.b64encode(raw).decode()+'\n');out.flush();os.fsync(out.fileno())
    key=Ed25519PrivateKey.from_private_bytes(base64.b64decode(private.read_text().strip()))
    raw=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    public.parent.mkdir(parents=True,exist_ok=True)
    encoded=base64.b64encode(raw).decode()+'\n'
    if public.exists() and public.read_text()!=encoded:raise RuntimeError('Clé publique incohérente : restauration explicite requise')
    public.write_text(encoded);os.chmod(public,0o644)
    return key

def initialize(s,invitation_file):
    db.migrate(s.db)
    with s.db.begin() as conn:
        owner=db.row(conn,db.users,db.users.c.name_key=='raph563')
        if owner:return owner['id']
        owner_id=db.uid();conn.execute(insert(db.users).values(id=owner_id,email=None,name='Raph563',name_key='raph563',password=None,role='admin',status='invited',created=time.time(),bio='Collection personnelle partagée avec Grocyste.',preferences={},recovery=[],totp_counter=-1))
        token=s.issue_token(conn,owner_id,'invite',seconds=7*86400)
        path=Path(invitation_file);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as out:json.dump({'url':s.origin+'/setup#token='+token,'expires_at':time.time()+7*86400},out);out.flush();os.fsync(out.fileno())
        return owner_id

def seed(s,path,key,catalog_public_key,owner_id):
    path=Path(path);manifest=json.loads((path/'manifest.json').read_text(encoding='utf-8'))
    trusted=Ed25519PublicKey.from_public_bytes(base64.b64decode(Path(catalog_public_key).read_text().strip()))
    trusted.verify(base64.b64decode((path/'manifest.sig').read_text().strip()),canonical(manifest).encode())
    if manifest['id']!='public-catalog' or manifest['version']!='1.0.0':raise RuntimeError('Le seed exige le catalogue qualifié 1.0.0')
    records=[]
    for name,entry in manifest['files'].items():
        if not (name=='data/products.json' or name.startswith('data/recipes-') and name.endswith('.json')):continue
        file=(path/name).resolve()
        if not file.is_relative_to(path.resolve()) or file.is_symlink():raise RuntimeError('Chemin seed interdit')
        raw=file.read_bytes()
        if len(raw)!=entry['size'] or digest(raw)!=entry['sha256']:raise RuntimeError('Fichier seed altéré')
        records.extend(json.loads(raw))
    if sum(r['kind']=='recipe' for r in records)!=5098 or sum(r['kind']=='product' for r in records)!=690:raise RuntimeError('Collection initiale incomplète')
    product_ids={r['id'] for r in records if r['kind']=='product'}
    with s.db.begin() as conn:
        s.lock(conn,'seed-v1')
        for record in records:
            entry_id=record['id']
            if db.row(conn,db.entries,db.entries.c.id==entry_id):continue
            data={k:v for k,v in record.items() if k not in ('id','kind')}
            data.setdefault('description','');data.setdefault('language','fr');data.setdefault('tags',[]);data.setdefault('images',[])
            data['rights_confirmed']=True;data['attribution']=['Collection Raph563 — fiches factuelles'] if data.get('origin')=='shared-facts' else ['Contributeurs de Wikilivres/Wikibooks ; historique conservé dans la fiche']
            if record['kind']=='product':
                if data.get('parent'):data['parent']={'id':data['parent'],'revision':1}
                data['conversions']=[]
            else:
                for ingredient in data['ingredients']:
                    if isinstance(ingredient,dict) and ingredient.get('product'):ingredient['product']={'id':ingredient['product'],'revision':1}
                data['subrecipes']=[{'id':v['recipe'],'revision':1} for v in data.get('subrecipes',[]) if isinstance(v,dict) and v.get('recipe')]
            owner=owner_id if record.get('origin')=='shared-facts' else None
            entry={'id':entry_id,'kind':record['kind'],'owner_id':owner,'published':1,'latest':1,'created':time.time(),'withdrawn':False}
            revision={'id':entry_id,'revision':1,'author_id':owner,'state':'published','content':data,'name':data['name'],'language':data['language'],'search':content.search_text(data),'created':time.time(),'reviewed':time.time()}
            sha,signature=content.sign(entry,revision,key);revision.update(digest=sha,signature=signature)
            conn.execute(insert(db.entries).values(**entry));conn.execute(insert(db.revisions).values(**revision))
        packs=[('k-raph563-produits','Produits de la collection Raph563',sorted(product_ids)),
               ('k-raph563-recettes','Les 70 recettes de la collection Raph563',sorted(r['id'] for r in records if r['kind']=='recipe' and r.get('origin')=='shared-facts'))]
        for entry_id,name,ids in packs:
            if db.row(conn,db.entries,db.entries.c.id==entry_id):continue
            data=content.validate('pack',{'name':name,'language':'fr','description':'Fiches publiques ; aucun stock, achat, prix payé ni information domestique. Les méthodes et photos tierces restent à leur source.','items':[{'id':v,'revision':1} for v in ids],'rights_confirmed':True,'attribution':['Collection Raph563']})
            entry={'id':entry_id,'kind':'pack','owner_id':owner_id,'published':1,'latest':1,'created':time.time(),'withdrawn':False}
            revision={'id':entry_id,'revision':1,'author_id':owner_id,'state':'published','content':data,'name':name,'language':'fr','search':content.search_text(data),'created':time.time(),'reviewed':time.time()}
            sha,signature=content.sign(entry,revision,key);revision.update(digest=sha,signature=signature)
            conn.execute(insert(db.entries).values(**entry));conn.execute(insert(db.revisions).values(**revision))
        for entry_id,_,_ in packs:
            e=db.row(conn,db.entries,db.entries.c.id==entry_id);r=db.row(conn,db.revisions,and_(db.revisions.c.id==entry_id,db.revisions.c.revision==1));content.graph(conn,e,r)
    return {'products':690,'recipes':5098,'personal_recipes':70,'packs':2}

def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['keys','init','seed']);p.add_argument('--private-key');p.add_argument('--public-key');p.add_argument('--invitation-file');p.add_argument('--catalog');p.add_argument('--catalog-key');args=p.parse_args()
    if args.command=='keys':keys(args.private_key,args.public_key);print('Clés de données préparées');return
    from .app import create_app
    app=create_app();s=app.extensions['community']
    with app.app_context():
        if args.command=='init':initialize(s,args.invitation_file);print('Schéma et invitation privée préparés')
        elif args.command=='seed':
            with s.db.connect() as conn:owner=db.row(conn,db.users,db.users.c.name_key=='raph563')
            key=Ed25519PrivateKey.from_private_bytes(base64.b64decode(Path(args.private_key).read_text().strip()))
            print(json.dumps(seed(s,args.catalog,key,args.catalog_key,owner['id'])))

if __name__=='__main__':main()
