"""Reviewed data format. Content never becomes an executable addon."""
import base64, copy, hashlib, re, time
from sqlalchemy import select, insert, update, delete, func, and_
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from . import db
from .security import Error, canonical, text, finite, integer, identifier, public_url, bounds, normalized

COMMON={'name','language','description','tags','source','license','license_url','attribution','images','rights_confirmed'}
PRODUCT={'brand','sub_brand','barcodes','stock_unit','purchase_unit','parent','reference_price','nutrition','conversions'}
RECIPE={'base_servings','ingredients','instructions','notes','subrecipes','availability'}
PACK={'items'}
LICENSES={'CC-BY-SA-4.0','CC-BY-4.0','CC0-1.0','public-domain'}
LICENSE_URLS={'CC-BY-SA-4.0':'https://creativecommons.org/licenses/by-sa/4.0/',
              'CC-BY-4.0':'https://creativecommons.org/licenses/by/4.0/',
              'CC0-1.0':'https://creativecommons.org/publicdomain/zero/1.0/',
              'public-domain':'https://creativecommons.org/publicdomain/mark/1.0/'}

def strings(value,limit=100,maximum=2000):
    if not isinstance(value,list) or len(value)>limit:raise Error('Liste invalide')
    return [text(v,maximum) for v in value]

def ref(value):
    if not isinstance(value,dict) or set(value)!={'id','revision'}:raise Error('Référence versionnée requise')
    return {'id':identifier(value['id']),'revision':integer(value['revision'])}

def validate(kind,value):
    if kind not in ('product','recipe','pack') or not isinstance(value,dict):raise Error('Type de fiche invalide')
    bounds(value)
    allowed=COMMON|{'product':PRODUCT,'recipe':RECIPE,'pack':PACK}[kind]
    if set(value)-allowed:raise Error('Champ non partageable ou inconnu')
    result=copy.deepcopy(value)
    result['name']=text(value.get('name'),500,1)
    result['language']=value.get('language','fr')
    if result['language'] not in ('fr','en'):raise Error('Langue non prise en charge')
    result['description']=text(value.get('description',''),20_000)
    result['tags']=strings(value.get('tags',[]),40,200)
    result['source']=public_url(value.get('source'))
    result['license']=value.get('license','CC-BY-SA-4.0')
    if result['license'] not in LICENSES:raise Error('Licence non prise en charge')
    result['license_url']=LICENSE_URLS[result['license']]
    if value.get('rights_confirmed') is not True:raise Error('Confirmer les droits de partage avant soumission')
    result['rights_confirmed']=True
    result['attribution']=strings(value.get('attribution',[]),30,2000)
    result['images']=strings(value.get('images',[]),12,64)
    if any(not re.fullmatch(r'[a-f0-9]{64}',v) for v in result['images']):raise Error('Image invalide')
    if kind=='product':
        result['brand']=text(value.get('brand') or '',300)
        result['sub_brand']=text(value.get('sub_brand') or '',300)
        result['barcodes']=strings(value.get('barcodes',[]),30,14)
        if any(not re.fullmatch(r'(?:\d{8}|\d{12,14})',v) for v in result['barcodes']):raise Error('Code-barres invalide')
        result['stock_unit']=text(value.get('stock_unit'),100,1)
        result['purchase_unit']=text(value.get('purchase_unit') or result['stock_unit'],100,1)
        result['parent']=ref(value['parent']) if value.get('parent') else None
        price=value.get('reference_price')
        if price is not None:
            if not isinstance(price,dict) or set(price)-{'amount','currency','package_quantity','package_unit','observed_at','source','status','scope'}:raise Error('Prix de référence invalide')
            if finite(price.get('amount'))<0 or price.get('currency') not in ('EUR','USD','GBP','CHF','CAD'):raise Error('Prix de référence invalide')
            finite(price.get('package_quantity'),positive=True);text(price.get('package_unit'),100,1)
            if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z',text(price.get('observed_at'),40,1)):raise Error('Date du prix requise')
            public_url(price.get('source'),nullable=False)
            price['status']='historical-unreverified';price['scope']='Référence publique datée, sans prix d’achat personnel.'
        nutrition=value.get('nutrition')
        if nutrition is not None:
            if not isinstance(nutrition,dict) or set(nutrition)-{'energy_kcal','basis_amount','basis_unit','source','status'}:raise Error('Nutrition invalide')
            if finite(nutrition.get('energy_kcal'))<0:raise Error('Énergie invalide')
            finite(nutrition.get('basis_amount'),positive=True);text(nutrition.get('basis_unit'),100,1);public_url(nutrition.get('source'),nullable=False)
            nutrition['status']='historical-unreverified'
        result['reference_price']=price;result['nutrition']=nutrition
        conversions=value.get('conversions',[])
        if not isinstance(conversions,list) or len(conversions)>30:raise Error('Conversions invalides')
        for c in conversions:
            if not isinstance(c,dict) or set(c)!={'from','to','factor','source','proven'} or c['proven'] is not True:raise Error('Conversion non prouvée')
            text(c['from'],100,1);text(c['to'],100,1);finite(c['factor'],positive=True);text(c['source'],2000,1)
        result['conversions']=conversions
    elif kind=='recipe':
        result['base_servings']=finite(value.get('base_servings'),positive=True,nullable=True)
        ingredients=value.get('ingredients',[])
        if not isinstance(ingredients,list) or not 1<=len(ingredients)<=500:raise Error('Ingrédients absents ou trop nombreux')
        for item in ingredients:
            if isinstance(item,str):text(item,2000,1);continue
            if not isinstance(item,dict) or set(item)-{'name','product','quantity','unit','group','variable','note','optional'}:raise Error('Ingrédient invalide')
            text(item.get('name'),500,1);text(item.get('unit') or '',100)
            if item.get('product') is not None:ref(item['product'])
            if item.get('quantity') is not None and finite(item['quantity'])<0:raise Error('Quantité négative')
            for field in ('group','variable','note'):
                if item.get(field) is not None:text(item[field],2000)
            if 'optional' in item and type(item['optional']) is not bool:raise Error('Indicateur facultatif invalide')
        result['ingredients']=ingredients
        result['instructions']=strings(value.get('instructions',[]),500,6000)
        result['notes']=strings(value.get('notes',[]),100,6000)
        result['availability']='text' if result['instructions'] else 'source-only'
        result['subrecipes']=[ref(v) for v in value.get('subrecipes',[])]
        if len(result['subrecipes'])>50:raise Error('Trop de sous-recettes')
    else:
        items=value.get('items')
        if not isinstance(items,list) or not 1<=len(items)<=1000:raise Error('Un pack contient de 1 à 1 000 fiches')
        result['items']=[ref(v) for v in items]
        if len({v['id'] for v in result['items']})!=len(items):raise Error('Fiche dupliquée dans le pack')
    return result

def references(kind,content):
    values=[]
    if kind=='product' and content.get('parent'):values.append(content['parent'])
    if kind=='recipe':
        values.extend(v['product'] for v in content.get('ingredients',[]) if isinstance(v,dict) and v.get('product'))
        values.extend(content.get('subrecipes',[]))
    if kind=='pack':values.extend(content.get('items',[]))
    return values

def search_text(content):
    parts=[content.get('name',''),content.get('description',''),*content.get('tags',[]),*content.get('barcodes',[])]
    parts.extend(v if isinstance(v,str) else v.get('name','') for v in content.get('ingredients',[]))
    return normalized(' '.join(parts))[:100_000]

def public_record(entry,revision):
    return {'schema':'grocyste-share-v1','id':entry['id'],'kind':entry['kind'],
            'revision':revision['revision'],'content':revision['content'],'created_at':revision['created']}

def envelope(entry,revision,public_key):
    return {'record':public_record(entry,revision),'sha256':revision['digest'],
            'signature':revision['signature'],'key_id':hashlib.sha256(public_key).hexdigest()}

def graph(conn,entry,revision,*,require_public=True):
    visited=set();active=set();ordered=[]
    def visit(e,r,depth):
        key=(e['id'],r['revision'])
        if key in active:raise Error('Dépendance cyclique',409)
        if key in visited:return
        if depth>12 or len(visited)>2000:raise Error('Graphe de dépendances trop grand')
        active.add(key)
        for v in references(e['kind'],r['content']):
            child=db.row(conn,db.entries,db.entries.c.id==v['id'])
            rev=db.row(conn,db.revisions,and_(db.revisions.c.id==v['id'],db.revisions.c.revision==v['revision']))
            if not child or not rev or child['withdrawn'] or (require_public and rev['state']!='published'):
                raise Error('Dépendance absente, non publiée ou retirée',409)
            if e['kind']=='pack' and child['kind']=='pack':raise Error('Un pack référence des produits ou recettes, pas un autre pack')
            if e['kind']=='product' and child['kind']!='product':raise Error('Parent produit invalide')
            if e['kind']=='recipe':
                product_ids={x['product']['id'] for x in r['content'].get('ingredients',[]) if isinstance(x,dict) and x.get('product')}
                if v['id'] in product_ids and child['kind']!='product':raise Error('Référence ingrédient invalide')
                if v['id'] not in product_ids and child['kind']!='recipe':raise Error('Sous-recette invalide')
            visit(child,rev,depth+1)
        active.remove(key);visited.add(key);ordered.append((e,r))
    visit(entry,revision,0)
    return ordered

def sign(entry,revision,key):
    value=canonical(public_record(entry,revision)).encode()
    return hashlib.sha256(value).hexdigest(),base64.b64encode(key.sign(value)).decode()

def summary(entry,revision,author=None):
    c=revision['content']
    return {'id':entry['id'],'revision':revision['revision'],'kind':entry['kind'],'name':c['name'],
            'language':c.get('language','fr'),'tags':c.get('tags',[]),'origin':c.get('origin','community'),
            'availability':c.get('availability'),'author':author,'images':c.get('images',[]),
            'created_at':revision['created'],'state':revision['state']}
