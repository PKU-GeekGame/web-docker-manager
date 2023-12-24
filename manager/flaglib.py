import hashlib

import string

def md5(cont):
    return hashlib.md5(cont.encode()).hexdigest()

def sha1(cont):
    return hashlib.sha1(cont.encode()).hexdigest()

def sha256(cont):
    return hashlib.sha256(cont.encode()).hexdigest()

def randomCase(flag,token):
    hasHead = False
    rcont=flag
    uid=int(hashlib.sha256(token.encode()).hexdigest(),16)
    if '{' in flag:
        assert flag.startswith('flag{')
        assert flag.endswith('}')
        hasHead = True
        rcont=flag[5:-1]
    rdlis=[]
    for i in range(len(rcont)):
        if rcont[i] in string.ascii_letters:
            rdlis.append(i)
    rdseed=(uid+233)*114547%123457
    for it in range(4):
        if not rdlis:
            return flag
        np=rdseed%len(rdlis)
        npp=rdlis[np]
        rdseed=(rdseed+233)*114547%123457
        del rdlis[np]
        px=rcont[npp]
        rcont=rcont[:npp]+(px.upper() if px in string.ascii_lowercase else px.lower())+rcont[npp+1:]
    rcont=('flag{'+rcont+'}') if hasHead else rcont
    return rcont