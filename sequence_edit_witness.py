# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
import hashlib
import json
import re
from datetime import datetime, timezone


def _require(ok: bool,message: str) -> None:
    if not ok:raise gl.vm.UserError('[EXPECTED] '+message)


def _canon(value) -> str:return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)


def _hash(value) -> str:return hashlib.sha256(_canon(value).encode()).hexdigest()


def _now() -> int:
    t=datetime.fromisoformat(gl.message_raw['datetime'].replace('Z','+00:00'))
    if t.tzinfo is None:t=t.replace(tzinfo=timezone.utc)
    d=t.astimezone(timezone.utc)-datetime(1970,1,1,tzinfo=timezone.utc)
    return d.days*86400+d.seconds


def _id(value: str) -> None:
    _require(isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,32}',value) is not None,'invalid ASCII identifier')


def _source(url: str,digest: str) -> None:
    m=re.fullmatch(r'https://raw\.githubusercontent\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9_.-]{1,100})/([0-9a-f]{40})/([A-Za-z0-9_.~/-]+)',url) if isinstance(url,str) and len(url)<=512 else None
    _require(m is not None,'commit-pinned public source required')
    owner,repo,commit,path=m.groups()
    _require(owner[0].isalnum() and owner[-1].isalnum() and '--' not in owner and repo not in ('.','..') and all(p not in ('','.','..') for p in path.split('/')),'commit-pinned public source requires safe namespace/path segments')
    _require(isinstance(digest,str) and re.fullmatch(r'[0-9a-f]{64}',digest) is not None,'invalid SHA256')


def _text(url: str,digest: str) -> tuple:
    response=gl.nondet.web.get(url,headers={'Accept':'application/octet-stream'})
    if response.status!=200 or response.body is None or len(response.body)>8192:raise gl.vm.UserError('[SOURCE] unavailable or oversized text')
    if hashlib.sha256(response.body).hexdigest()!=digest:raise gl.vm.UserError('[SOURCE] byte digest mismatch')
    try:text=response.body.decode('utf-8')
    except UnicodeError:raise gl.vm.UserError('[SOURCE] invalid UTF8 text')
    lines=[] if text=='' else text.split('\n')
    _require(len(lines)<=64,'LF line capacity')
    _require('\n'.join(lines).encode('utf-8')==response.body,'exact text reconstruction failed')
    return text,lines


def _step(op: str,i: int,j: int,values: dict) -> dict:
    return dict(values,op=op,source_index=i,target_index=j)


def _replay(a: list,b: list,script: list) -> tuple:
    i=0;j=0;cost=0;output=[]
    for action in script:
        _require(isinstance(action,dict) and action.get('source_index')==i and type(action.get('source_index')) is int and action.get('target_index')==j and type(action.get('target_index')) is int,'script cursor mismatch')
        op=action.get('op');common={'op','source_index','target_index'}
        if op=='MATCH':
            _require(set(action)==common|{'text'} and i<len(a) and j<len(b) and action['text']==a[i]==b[j],'invalid MATCH')
            output.append(action['text']);i+=1;j+=1
        elif op=='REPLACE':
            _require(set(action)==common|{'old','new'} and i<len(a) and j<len(b) and action['old']==a[i] and action['new']==b[j],'invalid REPLACE')
            output.append(action['new']);i+=1;j+=1;cost+=1
        elif op=='DELETE':
            _require(set(action)==common|{'text'} and i<len(a) and action['text']==a[i],'invalid DELETE')
            i+=1;cost+=1
        else:
            _require(op=='INSERT' and set(action)==common|{'text'} and j<len(b) and action['text']==b[j],'invalid INSERT')
            output.append(action['text']);j+=1;cost+=1
    _require(i==len(a) and j==len(b) and output==b,'incomplete or wrong-target script')
    return output,cost


def _derive(a: list,b: list,target_text: str) -> dict:
    m=len(a);n=len(b);dp=[[0]*(n+1) for _ in range(m+1)]
    for i in range(m,-1,-1):
        for j in range(n,-1,-1):
            if i==m:dp[i][j]=n-j
            elif j==n:dp[i][j]=m-i
            else:dp[i][j]=min((0 if a[i]==b[j] else 1)+dp[i+1][j+1],1+dp[i+1][j],1+dp[i][j+1])
    i=0;j=0;script=[]
    while i<m or j<n:
        if i<m and j<n and a[i]==b[j] and dp[i][j]==dp[i+1][j+1]:
            script.append(_step('MATCH',i,j,{'text':a[i]}));i+=1;j+=1
        elif i<m and j<n and dp[i][j]==1+dp[i+1][j+1]:
            script.append(_step('REPLACE',i,j,{'old':a[i],'new':b[j]}));i+=1;j+=1
        elif i<m and dp[i][j]==1+dp[i+1][j]:
            script.append(_step('DELETE',i,j,{'text':a[i]}));i+=1
        else:
            _require(j<n and dp[i][j]==1+dp[i][j+1],'invalid optimum cursor')
            script.append(_step('INSERT',i,j,{'text':b[j]}));j+=1
    output,cost=_replay(a,b,script)
    _require(cost==dp[0][0] and '\n'.join(output)==target_text,'optimal script target reconstruction failed')
    return {'source_lines':a,'target_lines':b,'cost':cost,'script':script,'target_sha256':hashlib.sha256(target_text.encode('utf-8')).hexdigest()}


def _capture(left_url: str,left_hash: str,right_url: str,right_hash: str,binding: dict) -> dict:
    def leader() -> dict:
        left_text,a=_text(left_url,left_hash);right_text,b=_text(right_url,right_hash)
        return {'binding':binding,'result':_derive(a,b,right_text)}
    def validator(proposed: gl.vm.Result) -> bool:
        if not isinstance(proposed,gl.vm.Return):return False
        try:
            # Fresh retrieval of BOTH source bytes, full suffix DP, canonical script and exact replay.
            return _canon(leader())==_canon(proposed.calldata)
        except Exception:return False
    return gl.vm.run_nondet_unsafe(leader,validator)


class SequenceEditWitness(gl.Contract):
    owner: Address
    edits: TreeMap[str,str]
    registrations: u256

    def __init__(self):self.owner=gl.message.sender_address

    def _owner(self) -> None:_require(gl.message.sender_address==self.owner,'owner only')

    def _load(self,edit_id: str) -> dict:
        _require(edit_id in self.edits,'unknown edit');return json.loads(self.edits[edit_id])

    def _cas(self,d: dict,revision: int) -> None:_require(type(revision) is int and revision==d['revision'],'stale revision')

    def _save(self,edit_id: str,d: dict) -> None:self.edits[edit_id]=_canon(d)

    def _phase(self,d: dict,status: str) -> None:
        _require(len(d['history'])<4,'history capacity');d['status']=status;d['revision']+=1
        d['history'].append({'status':status,'revision':d['revision'],'at':_now()})

    @gl.public.write
    def register(self,edit_id: str,left_url: str,left_sha256: str,right_url: str,right_sha256: str) -> None:
        self._owner();_id(edit_id);_source(left_url,left_sha256);_source(right_url,right_sha256)
        _require(edit_id not in self.edits,'edit ID already used');_require(int(self.registrations)<8,'registration capacity')
        d={'edit_id':edit_id,'owner':self.owner.as_hex.lower(),'left_url':left_url,'left_sha256':left_sha256,'right_url':right_url,'right_sha256':right_sha256,'registered_at':_now(),'status':'REGISTERED','revision':0,'certificate_id':'','result':None,'attestation':None,'reason':'','history':[{'status':'REGISTERED','revision':0,'at':_now()}]}
        self._save(edit_id,d);self.registrations=u256(int(self.registrations)+1)

    @gl.public.write
    def certify(self,edit_id: str,expected_revision: int) -> str:
        d=self._load(edit_id);self._cas(d,expected_revision);_require(d['status']=='REGISTERED','edit not registered for certification')
        binding={'protocol':'SequenceEditWitness-v1','chain_id':int(gl.message.chain_id),'contract':gl.message.contract_address.as_hex.lower(),'owner':d['owner'],'edit_id':edit_id,'left_url':d['left_url'],'left_sha256':d['left_sha256'],'right_url':d['right_url'],'right_sha256':d['right_sha256'],'registered_at':d['registered_at'],'expected_revision':expected_revision,'certifier':gl.message.sender_address.as_hex.lower(),'certified_at':_now()}
        packet=_capture(d['left_url'],d['left_sha256'],d['right_url'],d['right_sha256'],binding)
        d['attestation']=packet;d['result']=packet['result'];d['certificate_id']=_hash(['SequenceEditWitness-certificate-v1',packet])
        self._phase(d,'CERTIFIED');self._save(edit_id,d);return d['certificate_id']

    @gl.public.write
    def activate(self,edit_id: str,expected_revision: int,certificate_id: str) -> None:
        self._owner();d=self._load(edit_id);self._cas(d,expected_revision);_require(d['status']=='CERTIFIED','certificate not ready')
        _require(isinstance(certificate_id,str) and certificate_id==d['certificate_id'],'certificate mismatch')
        self._phase(d,'ACTIVE');self._save(edit_id,d)

    @gl.public.write
    def revoke(self,edit_id: str,expected_revision: int,reason: str) -> None:
        self._owner();d=self._load(edit_id);self._cas(d,expected_revision);_require(d['status']!='REVOKED','edit already revoked')
        _require(isinstance(reason,str) and 1<=len(reason)<=200 and reason==reason.strip(),'revocation reason required')
        d['reason']=reason;self._phase(d,'REVOKED');self._save(edit_id,d)

    @gl.public.view
    def get_edit(self,edit_id: str) -> dict:return self._load(edit_id)

    @gl.public.view
    def is_active(self,edit_id: str,certificate_id: str,expected_revision: int) -> bool:
        if edit_id not in self.edits:return False
        d=self._load(edit_id);return d['status']=='ACTIVE' and isinstance(certificate_id,str) and certificate_id==d['certificate_id'] and type(expected_revision) is int and expected_revision==d['revision']

    @gl.public.view
    def get_configuration(self) -> dict:
        return {'protocol':'SequenceEditWitness-v1','owner':self.owner.as_hex.lower(),'registrations':int(self.registrations),'max_edits':8,'max_source_bytes':8192,'max_lf_elements':64,'max_history':4,'tie_order':['MATCH','REPLACE','DELETE','INSERT'],'normalization':'none; empty=[] else split LF with trailing empty preserved'}
