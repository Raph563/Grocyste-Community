"""Authentication primitives and strict, finite data validation."""
import base64, hashlib, hmac, json, math, os, re, secrets, struct, time, unicodedata
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from cryptography.fernet import Fernet
from PIL import Image, ImageOps, UnidentifiedImageError

PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
Image.MAX_IMAGE_PIXELS = 20_000_000
ID = re.compile(r"^[a-z][a-z0-9-]{0,79}$")

class Error(Exception):
    def __init__(self, message, status=400, code="invalid_request"):
        super().__init__(message); self.status=status; self.code=code

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",",":"), allow_nan=False)

def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()

def opaque(): return secrets.token_urlsafe(32)

def text(value, maximum=500, minimum=0):
    if not isinstance(value, str) or not minimum <= len(value) <= maximum or "\x00" in value:
        raise Error("Texte absent ou trop long")
    return value.strip()

def finite(value, *, positive=False, nullable=False):
    if value is None and nullable: return None
    if isinstance(value, bool) or not isinstance(value, (int,float)) or not math.isfinite(value) or (positive and value<=0):
        raise Error("Quantité invalide")
    return value

def identifier(value):
    if not isinstance(value,str) or not ID.fullmatch(value): raise Error("Identifiant invalide")
    return value

def integer(value, low=1, high=1_000_000):
    if type(value) is not int or not low <= value <= high: raise Error("Nombre entier invalide")
    return value

def normalized(value):
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())

def email(value):
    value=text(value,320,3)
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}",value):
        raise Error("Adresse email invalide")
    local,domain=value.rsplit("@",1)
    if len(local)>64 or local.startswith('.') or local.endswith('.') or '..' in local: raise Error("Adresse email invalide")
    # Preserve dots, '+' aliases and local-part casing: do not merge distinct identities.
    return local+"@"+domain.lower()

def password(value):
    if not isinstance(value,str) or not 15 <= len(value) <= 128: raise Error("Choisir un mot de passe de 15 à 128 caractères")
    return PASSWORDS.hash(value)

def verify_password(encoded,value):
    try: return PASSWORDS.verify(encoded,value) if encoded and isinstance(value,str) and len(value)<=128 else False
    except (VerifyMismatchError,VerificationError,InvalidHashError): return False

def public_url(value, nullable=True):
    if value is None and nullable:return None
    value=text(value,2000,8)
    try:u=urlsplit(value)
    except ValueError:raise Error("Lien invalide")
    if u.scheme!="https" or not u.hostname or u.username or u.password or u.port not in (None,443) or re.search(r"[\s\\]",value):
        raise Error("Seuls les liens HTTPS publics sont acceptés")
    # This validates hyperlinks only; no server downloads the supplied URL.
    return value

def secret_file(path, size=32):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if path.is_symlink():raise RuntimeError("Fichier secret interdit")
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"wb") as out:out.write(secrets.token_bytes(size));out.flush();os.fsync(out.fileno())
    except FileExistsError:pass
    data=path.read_bytes()
    if len(data)!=size:raise RuntimeError("Secret local corrompu")
    return data

class Vault:
    def __init__(self,key):self.cipher=Fernet(base64.urlsafe_b64encode(key))
    def seal(self,value):return self.cipher.encrypt(canonical(value).encode()).decode()
    def open(self,value):return json.loads(self.cipher.decrypt(value.encode()))

def csrf(secret,sid):return hmac.new(secret,sid.encode(),hashlib.sha256).hexdigest()

def totp(secret,at=None):
    counter=int((time.time() if at is None else at)//30)
    key=base64.b32decode(secret+'='*((8-len(secret)%8)%8))
    value=hmac.new(key,struct.pack('>Q',counter),hashlib.sha1).digest();offset=value[-1]&15
    return f"{(struct.unpack('>I',value[offset:offset+4])[0]&0x7fffffff)%1000000:06d}"

def totp_counter(secret,code,previous=-1,at=None):
    if not isinstance(code,str) or not re.fullmatch(r"\d{6}",code):return None
    at=time.time() if at is None else at
    for offset in (-1,0,1):
        counter=int(at//30)+offset
        if counter>previous and hmac.compare_digest(totp(secret,counter*30),code):return counter
    return None

def safe_image(raw):
    if not raw or len(raw)>10*1024*1024:raise Error("Image absente ou supérieure à 10 Mo",413)
    try:
        with Image.open(BytesIO(raw)) as source:
            if source.format not in ('JPEG','PNG','WEBP') or source.width*source.height>20_000_000:
                raise Error("Image non prise en charge ou trop grande")
            source.load();image=ImageOps.exif_transpose(source).convert('RGB');image.thumbnail((2400,2400))
            out=BytesIO();image.save(out,'JPEG',quality=88,optimize=True)
            return out.getvalue(),image.width,image.height
    except (UnidentifiedImageError,OSError,ValueError,Image.DecompressionBombError) as exc:
        raise Error("Image invalide") from exc

def bounds(value,depth=0):
    if depth>14:raise Error("Structure trop profonde")
    if isinstance(value,dict):
        if len(value)>2000:raise Error("Objet trop grand")
        for k,v in value.items():text(k,160);bounds(v,depth+1)
    elif isinstance(value,list):
        if len(value)>2000:raise Error("Liste trop grande")
        for v in value:bounds(v,depth+1)
    elif isinstance(value,str):text(value,300_000)
    elif isinstance(value,float):finite(value)
    elif value is not None and type(value) not in (bool,int):raise Error("Type de donnée invalide")
