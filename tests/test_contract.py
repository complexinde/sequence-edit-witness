import copy
import hashlib
import json
from pathlib import Path
import re
import pytest
from gltest.direct import create_address

ROOT=Path(__file__).parents[1];META=json.loads((ROOT/'fixtures/source.json').read_text());LEFT=(ROOT/'fixtures/left.txt').read_bytes();RIGHT=(ROOT/'fixtures/right.txt').read_bytes()
def sha(body):return hashlib.sha256(body).hexdigest()
def deploy(vm,build):
    vm.warp('2026-10-21T00:00:00Z');c=build(str(ROOT/'sequence_edit_witness.py'),sdk_version='v0.2.12');assert hasattr(c,'register'),'SequenceEditWitness API not implemented';return c
def mocks(vm,left=LEFT,right=RIGHT):
    vm.clear_mocks()
    for side,body in [('left',left),('right',right)]:vm.mock_web(re.escape(META[side]['test_url']),{'status':200,'body':body})
def register(vm,c,left=LEFT,right=RIGHT,ident='edit'):
    mocks(vm,left,right);c.register(ident,META['left']['test_url'],sha(left),META['right']['test_url'],sha(right))
def step(op,i,j,**values):return dict(op=op,source_index=i,target_index=j,**values)
def assert_application(left,right,script):
    # Straight replay of the emitted actions, no host optimum/edit algorithm.
    source=[] if left==b'' else left.decode().split('\n');output=[];cursor=0
    for action in script:
        assert action['source_index']==cursor and action['target_index']==len(output)
        if action['op']=='MATCH':assert source[cursor]==action['text'];output.append(action['text']);cursor+=1
        elif action['op']=='REPLACE':assert source[cursor]==action['old'];output.append(action['new']);cursor+=1
        elif action['op']=='DELETE':assert source[cursor]==action['text'];cursor+=1
        else:assert action['op']=='INSERT';output.append(action['text'])
    assert cursor==len(source) and '\n'.join(output).encode()==right

def test_literal_script_complete_optimal_and_live_state(direct_vm,direct_deploy):
    c=deploy(direct_vm,direct_deploy);register(direct_vm,c);cert=c.certify('edit',0);r=c.get_edit('edit')['result']
    assert r['cost']==1 and r['source_lines']==['alpha','beta',''] and r['target_lines']==['alpha','gamma','']
    assert r['script']==[step('MATCH',0,0,text='alpha'),step('REPLACE',1,1,old='beta',new='gamma'),step('MATCH',2,2,text='')]
    assert_application(LEFT,RIGHT,r['script']);assert direct_vm.run_validator() is True
    c.activate('edit',1,cert);assert c.is_active('edit',cert,2) is True

@pytest.mark.parametrize('left,right,cost,ops',[(b'',b'',0,[]),(b'',b'a',1,['INSERT']),(b'a',b'',1,['DELETE']),(b'a\n',b'a',1,['MATCH','DELETE']),(b'a\r\n',b'a\n',1,['REPLACE','MATCH']),('Ω\n雪'.encode(),'Ω\n雨'.encode(),1,['MATCH','REPLACE']),(b'a\nb',b'b\na',2,['REPLACE','REPLACE']),(b'a\na',b'a',1,['MATCH','DELETE']),(b'a',b'a\na',1,['MATCH','INSERT']),(b'a\nb\nc',b'b\nc\nd',2,['DELETE','MATCH','MATCH','INSERT']),(b'',b'\n',2,['INSERT','INSERT']),('\ufeffa\u2028b'.encode(),b'a',1,['REPLACE'])])
def test_empty_newlines_unicode_and_multiple_optimum_ties(direct_vm,direct_deploy,left,right,cost,ops):
    c=deploy(direct_vm,direct_deploy);register(direct_vm,c,left,right);c.certify('edit',0);r=c.get_edit('edit')['result']
    assert r['cost']==cost and [s['op'] for s in r['script']]==ops
    assert_application(left,right,r['script']);assert direct_vm.run_validator() is True

@pytest.mark.parametrize('field',['cost','script','source_lines','target_lines','binding'])
def test_independent_validator_rejects_complete_shape_forgery(direct_vm,direct_deploy,field):
    c=deploy(direct_vm,direct_deploy);register(direct_vm,c);c.certify('edit',0);packet=copy.deepcopy(c.get_edit('edit')['attestation'])
    if field=='cost':packet['result']['cost']=0
    elif field=='script':packet['result']['script'][1]['new']='attacker'
    elif field=='source_lines':packet['result']['source_lines'][0]='attacker'
    elif field=='target_lines':packet['result']['target_lines'][0]='attacker'
    else:packet['binding']['edit_id']='other'
    assert direct_vm.run_validator(leader_result=packet) is False

def test_validator_refetches_both_sources(direct_vm,direct_deploy):
    c=deploy(direct_vm,direct_deploy);register(direct_vm,c);c.certify('edit',0)
    mocks(direct_vm,right=RIGHT+b' ');assert direct_vm.run_validator() is False
    mocks(direct_vm,left=LEFT+b' ');assert direct_vm.run_validator() is False

@pytest.mark.parametrize('kind',['left-unavailable','right-unavailable','left-drift','right-drift','invalid-utf8','bytes-over','lines-over'])
def test_invalid_or_changed_source_stays_registered(direct_vm,direct_deploy,kind):
    c=deploy(direct_vm,direct_deploy);left=LEFT;right=RIGHT
    if kind=='invalid-utf8':left=b'\xff'
    elif kind=='bytes-over':left=b'a'*8193
    elif kind=='lines-over':left=b'\n'*64
    register(direct_vm,c,left,right)
    if kind=='left-unavailable':
        direct_vm.clear_mocks();direct_vm.mock_web(re.escape(META['left']['test_url']),{'status':404,'body':b''})
    elif kind=='right-unavailable':
        direct_vm.clear_mocks();direct_vm.mock_web(re.escape(META['left']['test_url']),{'status':200,'body':left});direct_vm.mock_web(re.escape(META['right']['test_url']),{'status':503,'body':b''})
    elif kind=='left-drift':mocks(direct_vm,left+b' ',right)
    elif kind=='right-drift':mocks(direct_vm,left,right+b' ')
    with direct_vm.expect_revert():c.certify('edit',0)
    assert c.get_edit('edit')['status']=='REGISTERED' and c.get_edit('edit')['revision']==0
    c.revoke('edit',0,'No valid source.');assert c.get_edit('edit')['status']=='REVOKED'

def test_exact_upper_source_bounds_are_accepted(direct_vm,direct_deploy):
    c=deploy(direct_vm,direct_deploy);left=b'x'*8192;register(direct_vm,c,left,left);c.certify('edit',0)
    assert c.get_edit('edit')['result']['cost']==0
    lines=b'\n'*63;register(direct_vm,c,lines,lines,'sixtyfour');c.certify('sixtyfour',0)
    assert len(c.get_edit('sixtyfour')['result']['source_lines'])==64

def test_permissionless_certification_owner_cas_terminal_and_pair_binding(direct_vm,direct_deploy):
    c=deploy(direct_vm,direct_deploy);other=create_address('other')
    with direct_vm.prank(other):
        with direct_vm.expect_revert('owner only'):register(direct_vm,c)
    register(direct_vm,c)
    with direct_vm.prank(other):cert=c.certify('edit',0)
    with direct_vm.prank(other):
        with direct_vm.expect_revert('owner only'):c.activate('edit',1,cert)
        with direct_vm.expect_revert('owner only'):c.revoke('edit',1,'withdraw')
    for revision in [0,True]:
        with direct_vm.expect_revert('revision'):c.activate('edit',revision,cert)
    with direct_vm.expect_revert('certificate'):c.activate('edit',1,'00'*32)
    register(direct_vm,c,ident='other');othercert=c.certify('other',0);assert cert!=othercert
    with direct_vm.expect_revert('certificate'):c.activate('other',1,cert)
    c.activate('edit',1,cert);direct_vm.clear_mocks();c.revoke('edit',2,'Withdraw pair.')
    assert c.is_active('edit',cert,2) is False and c.get_edit('edit')['revision']==3
    assert [x['status'] for x in c.get_edit('edit')['history']]==['REGISTERED','CERTIFIED','ACTIVE','REVOKED']
    with direct_vm.expect_revert():c.certify('edit',3)
    with direct_vm.expect_revert():c.activate('edit',3,cert)
    with direct_vm.expect_revert('already used'):register(direct_vm,c)

def test_url_digest_and_lifetime_capacity(direct_vm,direct_deploy):
    c=deploy(direct_vm,direct_deploy)
    with direct_vm.expect_revert('commit-pinned'):c.register('bad',META['left']['test_url'].replace('0'*40,'main'),sha(LEFT),META['right']['test_url'],sha(RIGHT))
    with direct_vm.expect_revert('SHA256'):c.register('bad',META['left']['test_url'],'0'*63,META['right']['test_url'],sha(RIGHT))
    for i in range(8):register(direct_vm,c,ident='e'+str(i))
    c.revoke('e0',0,'Withdraw record.')
    with direct_vm.expect_revert('capacity'):register(direct_vm,c,ident='overflow')

@pytest.mark.parametrize('side',['left','right'])
@pytest.mark.parametrize('owner,repo',[('owner','.'),('owner','..'),('.','repo'),('..','repo'),('-owner','repo'),('owner-','repo'),('a--b','repo'),('a'*40,'repo')])
def test_dot_namespaces_and_invalid_owner_never_register(direct_vm,direct_deploy,side,owner,repo):
    c=deploy(direct_vm,direct_deploy);url='https://raw.githubusercontent.com/'+owner+'/'+repo+'/'+'0'*40+'/file.txt';left=url if side=='left' else META['left']['test_url'];right=url if side=='right' else META['right']['test_url']
    with direct_vm.expect_revert('commit-pinned'):c.register('bad',left,sha(LEFT),right,sha(RIGHT))
    assert c.get_configuration()['registrations']==0

@pytest.mark.parametrize('side',['left','right'])
@pytest.mark.parametrize('owner,repo',[('a','.github'),('a-b','repo.name'),('a'*39,'_repo')])
def test_safe_boundary_namespace_is_not_overrejected(direct_vm,direct_deploy,side,owner,repo):
    c=deploy(direct_vm,direct_deploy);url='https://raw.githubusercontent.com/'+owner+'/'+repo+'/'+'0'*40+'/file.txt';left=url if side=='left' else META['left']['test_url'];right=url if side=='right' else META['right']['test_url']
    c.register('ok',left,sha(LEFT),right,sha(RIGHT));assert c.get_edit('ok')[side+'_url']==url
