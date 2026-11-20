"""Scan public OpenAPI specs for the five quality dimensions on BOLA-relevant endpoints.
Object endpoint = GET operation whose path ends with a {placeholder}."""
import sys, os, re, json, csv
import yaml
try:
    from yaml import CSafeLoader as L
except ImportError:
    from yaml import SafeLoader as L
OWNER=re.compile(r'^(owner|owner_?id|user_?id|account_?id|customer_?id|created_?by|creator|creator_?id|author|author_?id|tenant_?id|member_?id|profile_?id|organization_?id|org_?id)$',re.I)
def res(spec,o,depth=0):
    while isinstance(o,dict) and '$ref' in o and depth<20:
        r=o['$ref']
        if not isinstance(r,str) or not r.startswith('#/'): return {}
        cur=spec
        for k in r[2:].split('/'):
            k=k.replace('~1','/').replace('~0','~')
            if isinstance(cur,dict) and k in cur: cur=cur[k]
            else: return {}
        o=cur; depth+=1
    return o if isinstance(o,dict) else {}
def props(spec,s,depth=0,seen=None):
    seen=seen or set()
    s=res(spec,s)
    if not s or depth>4 or id(s) in seen: return set()
    seen.add(id(s)); out=set()
    for k,v in (s.get('properties') or {}).items():
        out.add(k)
        if depth<1: out|=props(spec,v,depth+1,seen)  # one nested level, e.g. data: {...}
    for comb in ('allOf','oneOf','anyOf'):
        for x in s.get(comb) or []: out|=props(spec,x,depth+1,seen)
    if s.get('type')=='array' or 'items' in s: out|=props(spec,s.get('items'),depth+1,seen)
    return out
def scan(path):
    with open(path,'rb') as f: spec=yaml.load(f,Loader=L)
    if not isinstance(spec,dict) or not isinstance(spec.get('paths'),dict): return None
    v3='openapi' in spec
    gsec=bool(spec.get('security'))
    rows=[]
    for p,item in spec['paths'].items():
        item=res(spec,item)
        if not isinstance(p,str) or not re.search(r'\{[^}]+\}/?$',p) or 'get' not in item: continue
        op=res(spec,item.get('get'))
        name=re.findall(r'\{([^}]+)\}',p)[-1]
        params=[res(spec,x) for x in (item.get('parameters') or [])+(op.get('parameters') or []) if isinstance(x,dict)]
        prm=[x for x in params if x.get('in')=='path' and x.get('name')==name]
        prm=prm[-1] if prm else None
        sch=res(spec,prm.get('schema')) if prm and v3 else (prm or {})
        ex=bool(prm and ('example' in prm or prm.get('examples') or 'x-example' in prm or 'example' in sch or sch.get('examples') or 'enum' in sch))
        typ=(sch.get('type') or '') if prm else ''
        fmt=(sch.get('format') or '') if prm else ''
        sec_op=op.get('security')
        sec=bool(sec_op) if sec_op is not None else gsec
        resp=op.get('responses') or {}
        ok=None
        for c in ('200','201','2XX','2xx',200,201):
            if c in resp: ok=res(spec,resp[c]); break
        rs=None
        if ok:
            if v3:
                for mt,m in (ok.get('content') or {}).items():
                    if isinstance(m,dict) and m.get('schema'): rs=m['schema']; break
            else: rs=ok.get('schema')
        pn=props(spec,rs) if rs else set()
        rows.append(dict(spec=path,path=p,param_documented=prm is not None,example=ex,id_type=typ,id_format=fmt,
                         security=sec,response_schema=bool(rs),owner_field=any(OWNER.match(k) for k in pn if isinstance(k,str))))
    return rows,bool(spec.get('securityDefinitions') or (spec.get('components') or {}).get('securitySchemes'))
if __name__=='__main__':
    root,listfile,out=sys.argv[1:4]
    files=open(listfile).read().splitlines()
    allrows=[]; specs=[]; errs=0
    for f in files:
        try: r=scan(os.path.join(root,f))
        except Exception as e: errs+=1; continue
        if r is None: errs+=1; continue
        rows,has_schemes=r; allrows+=rows; specs.append(dict(spec=f,object_endpoints=len(rows),has_security_schemes=has_schemes))
    with open(out+'_endpoints.csv','w',newline='') as fh:
        w=csv.DictWriter(fh,fieldnames=list(allrows[0])); w.writeheader(); w.writerows(allrows)
    with open(out+'_specs.csv','w',newline='') as fh:
        w=csv.DictWriter(fh,fieldnames=list(specs[0])); w.writeheader(); w.writerows(specs)
    print('specs parsed',len(specs),'errors',errs,'object endpoints',len(allrows))
