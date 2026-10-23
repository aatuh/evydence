#!/usr/bin/env python3
"""Derive image changes from Git data and assess qualified package observations."""
import copy
import hashlib
import json
from pathlib import Path
import re
import tempfile

import yaml

import dependency_admission as admission
import dependency_advisories as advisories
import dependency_classifier as classifiers
import dependency_collection as collection
import dependency_exception_reviews as reviews
import dependency_fixture_advisories as data_licenses
import dependency_git_objects as objects
import dependency_image_packages as packages
import dependency_images as images
import dependency_inputs as inputs
import dependency_inventory as inventory
import dependency_policy as policy
import dependency_review_provider as provider
from release_lifecycle import read_bytes
from support_matrix_artifacts import UniqueLoader

ROOT=Path(__file__).resolve().parents[1]
VIEW_SCHEMA='evydence-image-declarations.v1'
SCHEMA='evydence-image-admission.v1'


class ImageAdmissionError(ValueError):
    def __init__(self):super().__init__('invalid or incomplete trusted image admission context')


def require(value):
    if not value:raise ImageAdmissionError()


def encode(value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
    require(len(raw)<=8*1024*1024);return raw


def digest(value):return hashlib.sha256(encode(value)).hexdigest()


def view(reader,observed,work_root):
    """Discovery reads a separate private data view, never proposed executable code."""
    try:
        source=provider.sha(observed['source']['commit']);base=provider.sha(observed['trusted_base'])
        admission.component_rows(observed,source,base)
        frozen,contents=inputs.revision(reader,source)
        require(frozen==observed['source']);collection.verified_contents(frozen,contents,source)
        snapshot=observed['inventory'];generator=snapshot['generator']
        require(set(generator['files'])==set(inventory.GENERATOR_FILES))
        require(isinstance(snapshot['inputs'],dict) and all(name in contents
            and hashlib.sha256(contents[name]).hexdigest()==value for name,value in snapshot['inputs'].items()))
        receipt=generator['classifier'];base_tree,tree=reader.tree(base)
        require(receipt['schema']==classifiers.SCHEMA and receipt['trusted_base']==base and receipt['tree']==base_tree)
        replaced={};trusted={};code={};shadow=dict(contents)
        for name in inventory.GENERATOR_FILES:
            if name.endswith('.py'):raw=read_bytes(ROOT,name,inventory.MAX_BYTES);code[name]=raw
            else:
                require(name.endswith('.go') and name.startswith(classifiers.PACKAGE))
                entry=tree[name];record=receipt['sources'][name]
                require(entry['type']=='blob' and entry['mode'] in {'100644','100755'}
                        and record['git_blob']==entry['sha'] and record['mode']==entry['mode'])
                raw=reader.blob(provider.sha(entry['sha']))
                require(isinstance(raw,bytes) and len(raw)<=objects.MAX_BLOB_BYTES
                        and objects.object_id('blob',raw)==entry['sha']
                        and hashlib.sha256(raw).hexdigest()==record['sha256'])
            require(hashlib.sha256(raw).hexdigest()==generator['files'][name])
            shadow[name]=raw;trusted[name]=hashlib.sha256(raw).hexdigest()
        for name in images.GENERATOR_FILES:
            if name.endswith('.py'):
                raw=read_bytes(ROOT,name,inventory.MAX_BYTES);code[name]=raw;shadow[name]=raw
                trusted[name]=hashlib.sha256(raw).hexdigest()
            else:require(name in contents)
        for name,value in trusted.items():
            replaced[name]={'original_sha256':None if name not in contents else hashlib.sha256(contents[name]).hexdigest(),
                            'trusted_sha256':value}
        discovery={'schema':inventory.SCHEMA,'scope':'image-discovery-action-references-only','complete':False,
                   'generator':generator,'inputs':snapshot['inputs'],
                   'components':[row for row in snapshot['components'] if row['ecosystem']=='github-actions']}
        shadow['docs/reference/dependency-inventory.json']=encode(discovery)
        require(len(shadow['docs/reference/dependency-inventory.json'])<=objects.MAX_BLOB_BYTES)
        work_root=Path(work_root).absolute();require(not work_root.is_symlink() and work_root.is_dir())
        work=Path(tempfile.mkdtemp(prefix='dependency-image-view-',dir=work_root))
        for name,raw in shadow.items():
            path=work/provider.git_path(name);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with path.open('xb') as handle:handle.write(raw)
            path.chmod(0o600)
        collection.verify_export(work,shadow)
        rows,discovered=images.discover(work)
        for row in rows:
            if row['kind']!='source-build':continue
            configurations=[]
            for location in row['locations']:
                match=re.fullmatch(r'(docker-compose\.yml|compose\.production-like\.yml)#services/([A-Za-z0-9_.-]+)',location)
                require(match is not None)
                document=yaml.load(contents[match[1]].decode('utf-8'),Loader=UniqueLoader)
                build=document['services'][match[2]]['build']
                require(isinstance(build,dict) and set(build)=={'context','target'}
                        and build['context']=='./deploy/local-dependencies' and build['target'] in {'minio','mc'})
                configurations.append(build)
            require(all(value==configurations[0] for value in configurations))
            row['recipe_sha256']=digest({'dockerfile_sha256':hashlib.sha256(contents['deploy/local-dependencies/Dockerfile']).hexdigest(),
                                         'build':configurations[0]})
        collection.verify_export(work,shadow)
        require(all(read_bytes(ROOT,name,inventory.MAX_BYTES)==raw for name,raw in code.items()))
        return {'schema':VIEW_SCHEMA,'source_commit':source,'trusted_base':base,'declarations':rows,
                'source_inventory_sha256':digest(snapshot),'discovery_inventory_sha256':digest(discovery),
                'discovery_component_profile':'github-actions-only',
                'source_input_sha256':{name:hashlib.sha256(raw).hexdigest() for name,raw in contents.items()},
                'trusted_generator_sha256':trusted,'generator_substitutions':replaced,
                'discovery_input_sha256':{name:hashlib.sha256(raw).hexdigest() for name,raw in discovered.items()}}
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError,yaml.YAMLError):raise ImageAdmissionError() from None


def origins(row):
    values=row['locations'];require(isinstance(values,list) and 0<len(values)<=512)
    result=set()
    for value in values:
        require(isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_.@/#:-]{1,1024}',value))
        value=re.sub(r'@([0-9a-f]{40})(?=#runtime/image$)','',value)
        result.add(value)
    return result


def declarations(value,source,base):
    require(value['schema']==VIEW_SCHEMA and value['source_commit']==source and value['trusted_base']==base)
    rows=value['declarations'];require(isinstance(rows,list) and len(rows)<=64)
    result={}
    for row in rows:
        require(row['kind'] in {'registry','source-build','operator-selected'})
        key=(row['kind'],row['reference'],row.get('recipe_sha256'))
        require(key not in result);origins(row);result[key]=row
    return result


class Scanner:
    def __init__(self,executable,work_root):
        self.executable=Path(executable).absolute();self.work_root=Path(work_root)
        require(not self.work_root.is_symlink() and self.work_root.is_dir())
        recipe=images.tools.recipe_digest()
        require(images.tools.verify_installation(self.executable.parent,recipe)==self.executable)
        self.receipt={'binary_sha256':images.tools.file_digest(self.executable),'recipe_sha256':recipe}
        self.receipts=[]
        self.work=Path(tempfile.mkdtemp(prefix='dependency-image-admission-',dir=self.work_root))
        images.release_scanner.verify_tool(self.executable,self.work)
        self.verify()

    def verify(self):
        require(images.tools.file_digest(self.executable)==self.receipt['binary_sha256'])
        require(images.tools.recipe_digest()==self.receipt['recipe_sha256'])

    def scan(self,row):
        self.verify();require(row['kind']=='registry')
        resolution=images.registry.resolve(images.registry.reference(row['reference']))
        work=Path(tempfile.mkdtemp(prefix='scan-',dir=self.work))
        observation=images.scan(self.executable,row,resolution,work)
        raw=read_bytes(work,'scanner.json',policy.MAX_DOCUMENT_BYTES)
        result=packages.from_scanner(raw,observation)
        require([value['package'] for value in result]==observation['packages'])
        self.receipts.append({'kind':row['kind'],'reference':row['reference'],
            'manifest_digest':observation['manifest_digest'],'image_id':observation['image_id'],
            'scanner_output_sha256':observation['scanner_output_sha256'],'platform':observation['platform'],
            'package_count':len(result)})
        self.verify();return result


def effective(value,source_rows):
    package=value['package'];component=advisories.identity(value['component'])
    require(type(value['metadata_only']) is bool and (not value['metadata_only'] or (
        package['type']=='apk' and package['name'].startswith('.') and value['metadata_profile']=='package-manager-record'
        and value['advisory_query'] is None)))
    require(component['version']==package['version'] and (
        component['name']==package['name'] if component['ecosystem']=='gomod' else
        component['ecosystem']=='docker' and component['name'].endswith('/'+package['name'])))
    license=package['license'] if package['license_status']=='scanner-declared' else None
    profile='scanner-declared' if license is not None else 'unknown'
    source=source_rows.get(tuple(component.values()))
    if (component['ecosystem']=='gomod' and value['module_sum'] is not None and source is not None
            and source.get('source',{}).get('verification')=='go-mod-verify'
            and source['source'].get('sum')==value['module_sum']):
        known=source['license_status'] in admission.LICENSE_STATES and source['license'] is not None
        if package['license_status']=='not-found' and known:
            license=source['license'];profile='bound-module-source'
        elif license is not None:
            def tokens(expression):
                parser=policy._Expression(expression,set(),set());parser.evaluate()
                return tuple(token.casefold() for token in parser.tokens)
            if not known or tokens(license)!=tokens(source['license']):license=None;profile='conflicting-module-source'
    return {**component,'license':license},profile


def flatten(rows,scan,source_rows,*,locations=None):
    result={};count=0
    for row in rows:
        selected=set(row.get('assessment_origins',origins(row)))
        if locations is not None:selected&=locations
        if not selected:continue
        values=scan(row);require(isinstance(values,list) and 0<len(values)<=images.MAX_PACKAGES)
        for value in values:
            count+=1;require(count<=images.MAX_PACKAGES)
            component,profile=effective(value,source_rows)
            material={'component':component,'license_profile':profile,'advisory_query':value['advisory_query'],
                      'package_license_status':value['package']['license_status'],
                      'package_license_declarations':value['package']['license_declarations'],
                      'module_sum':value['module_sum'],'metadata_only':value['metadata_only'],
                      'metadata_profile':value['metadata_profile']}
            for origin in selected:
                key=(*advisories.identity(component).values(),origin)
                require(key in result or len(result)<admission.MAX_COMPONENTS)
                record={'component':component,'license_profile':profile,'source_sha256':digest(material),'projection':value}
                require(key not in result or result[key]==record);result[key]=record
    return result


def assess(reader,base,head,before,after,work_root,api,today,*,syft=None,review_api=None):
    """A change-only image profile; unsupported new artifacts remain non-passing."""
    try:
        base=provider.sha(base);head=provider.sha(head);require(base!=head)
        admission.component_rows(before,base,base);admission.component_rows(after,head,base)
        rules,policy_source=admission.load_policy(reader,base,today)
        old_view=view(reader,before,work_root);new_view=view(reader,after,work_root)
        old=declarations(old_view,base,base);new=declarations(new_view,head,base)
        changed=[];unchanged=[]
        old_origins=set().union(*(origins(row) for row in old.values())) if old else set()
        for key,row in sorted(new.items()):
            previous=old.get(key);new_origins=origins(row)-(origins(previous) if previous else set())
            if previous is not None and not new_origins:unchanged.append(copy.deepcopy(row));continue
            selected=new_origins if previous else origins(row)
            changed.append({**row,'assessment_origins':sorted(selected)})
        gaps=[row['kind']+':'+row['reference'] for row in changed if row['kind']!='registry']
        active=[row for row in changed if row['kind']=='registry']
        scanner=None;cache={};scanned=[]
        if active and syft is None:gaps.append('qualified-scanner-unavailable');active=[]
        if active:scanner=Scanner(syft,work_root)
        def scan(row):
            key=(row['kind'],row['reference'],row.get('recipe_sha256'))
            if key not in cache:cache[key]=scanner.scan(row);scanned.append({'kind':row['kind'],'reference':row['reference']})
            return cache[key]
        old_sources={tuple(advisories.identity(row).values()):row for row in before['inventory']['components']}
        new_sources={tuple(advisories.identity(row).values()):row for row in after['inventory']['components']}
        active_origins=set().union(*(set(row['assessment_origins']) for row in active)) if active else set()
        candidates=[row for row in old.values() if row['kind']=='registry' and origins(row)&active_origins]
        baseline=[row for row in candidates if images.registry.reference(row['reference'])['digest'] is not None]
        omissions=[{'reference':row['reference'],'reason':'mutable-baseline-reference'} for row in candidates if row not in baseline]
        previous=flatten(baseline,scan,old_sources,locations=active_origins)
        proposed=flatten(active,scan,new_sources,locations=active_origins)
        changes=[]
        for key,row in sorted(proposed.items()):
            prior=previous.get(key);projection=row['projection'];component=row['component']
            # Unknown package versions cannot establish unchanged source content.
            if (prior is not None and prior['source_sha256']==row['source_sha256']
                    and (projection['advisory_query'] is not None or projection['metadata_only'])):continue
            if projection['metadata_only']:
                observation={'status':'not-applicable-package-record','vulnerabilities':None}
                result={'passed':True,'violations':[],'exceptions':[]}
            else:
                observation=({'component':advisories.identity(component),'status':'unsupported','vulnerabilities':None}
                             if projection['advisory_query'] is None else api.observe_query(component,projection['advisory_query']))
                require(observation.get('component')==advisories.identity(component)
                        and observation.get('status') in {'observed','unsupported','unavailable'})
                if observation['status']=='observed':result=policy.assess_component(
                    {**component,'vulnerabilities':observation['vulnerabilities']},rules,today)
                else:
                    require(observation.get('vulnerabilities') is None)
                    result=data_licenses.assess_license(component,rules,today)
                    result['violations'].append('advisory_coverage_unknown');result['passed']=False
            changes.append({**component,'origin':key[-1],'added_origins':[] if key[-1] in old_origins else [key[-1]],
                            'source_sha256':row['source_sha256'],'license_profile':row['license_profile'],
                            'license_applicability':'not-applicable-no-payload' if projection['metadata_only'] else 'package-license',
                            'advisory_status':observation['status'],'vulnerabilities':copy.deepcopy(observation['vulnerabilities']),**result})
        used={identity for row in changes for identity in row['exceptions']}
        applicable={**rules,'exceptions':[row for row in rules['exceptions'] if row['id'] in used]}
        approvals=reviews.verify(applicable,review_api,today);require(reviews.verify(applicable,review_api,today)==approvals)
        if scanner is not None:scanner.verify()
        report={'schema':SCHEMA,'scope':'declared-image-changes-linux-amd64','complete_artifact_sbom':False,
                'base':base,'head':head,'policy':policy_source,'source_base':old_view,'source_head':new_view,
                'changed_declarations':changed,'unchanged_declarations':unchanged,'scanned':scanned,
                'baseline_omissions':omissions,
                'scan_receipts':[] if scanner is None else copy.deepcopy(scanner.receipts),
                'package_changes':changes,'coverage_gaps':sorted(set(gaps)),
                'image_coverage_verified':not gaps,'image_decision_passed':not gaps and all(row['passed'] for row in changes),
                'exception_reviews':approvals,'scanner':None if scanner is None else scanner.receipt,
                'advisory_receipts':copy.deepcopy(api.receipts)}
        encode(report);return report
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise ImageAdmissionError() from None
