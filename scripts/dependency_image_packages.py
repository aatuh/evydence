#!/usr/bin/env python3
"""Project image package source coordinates without exporting scanner private fields."""
import base64
import hashlib
import re
from urllib.parse import parse_qsl,unquote,urlsplit

import dependency_advisories as advisories
import dependency_images as images
import dependency_policy as policy


class PackageError(ValueError):
    def __init__(self):super().__init__('invalid or unbound image package source metadata')


def require(value):
    if not value:raise PackageError()


def package_name(value):
    return isinstance(value,str) and re.fullmatch(r'\.?[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}',value) is not None


def project(row):
    try:
        package=images.package(row);kind=package['type'];name=package['name'];version=package['version']
        parsed=urlsplit(package['purl']);qualifiers=dict(parse_qsl(parsed.query,strict_parsing=True,errors='strict'))
        component={'ecosystem':'docker','name':'image/'+hashlib.sha256(package['purl'].encode()).hexdigest()[:24]+'/'+name,'version':version}
        result={'package':package,'component':component,'advisory_query':None,'metadata_only':False,
                'module_sum':None,'go_compiler_version':None,'metadata_profile':'unknown'}
        metadata=row.get('metadata',{})
        if not isinstance(metadata,dict):return result
        if kind=='go-module':
            component.update(ecosystem='gomod',name=name)
            if row.get('metadataType')!='go-module-buildinfo-entry':return result
            compiler=metadata.get('goCompiledVersion')
            if isinstance(compiler,str) and re.fullmatch(r'go[0-9]+\.[0-9]+\.[0-9]+',compiler):result['go_compiler_version']=compiler
            checksum=metadata.get('h1Digest')
            if checksum is not None:
                require(isinstance(checksum,str) and checksum.startswith('h1:') and len(checksum)<=128)
                raw=base64.b64decode(checksum[3:],validate=True)
                require(len(raw)==32 and 'h1:'+base64.b64encode(raw).decode()==checksum)
                result['module_sum']=checksum
            if name=='stdlib':
                if result['go_compiler_version'] is not None and version==result['go_compiler_version']:
                    result['advisory_query']={'package':{'ecosystem':'Go','name':'stdlib'},'version':version[2:]}
            elif version not in {'UNKNOWN','(devel)'}:
                try:result['advisory_query']=advisories.query(component)
                except advisories.AdvisoryError:pass
            result['metadata_profile']='go-binary-buildinfo'
            return result
        expected={'apk':'apk-db-entry','deb':'dpkg-db-entry'}[kind]
        if (row.get('metadataType')!=expected or metadata.get('package')!=name or metadata.get('version')!=version
                or metadata.get('architecture')!=qualifiers.get('arch')):return result
        distro=qualifiers.get('distro','')
        if kind=='apk':
            match=re.fullmatch(r'alpine-([1-9][0-9]*\.[0-9]+)(?:\.[0-9]+)?',distro)
            if match is None or not unquote(parsed.path).startswith('apk/alpine/'):return result
            source=metadata.get('originPackage')
            if not package_name(source) or source!=qualifiers.get('upstream',name):return result
            component['name']='alpine/'+match[1]+'/'+name
            result['metadata_only']=(name.startswith('.') and source==name and type(metadata.get('installedSize')) is int
                                     and metadata['installedSize']==0 and metadata.get('files')==[])
            request={'package':{'ecosystem':'Alpine:v'+match[1],'name':source},'version':version}
        else:
            match=re.fullmatch(r'debian-([1-9][0-9]*)(?:\.[0-9]+)?',distro)
            if match is None or not unquote(parsed.path).startswith('deb/debian/'):return result
            component['name']='debian/'+match[1]+'/'+name
            source=metadata.get('source');source_version=metadata.get('sourceVersion')
            if source=='':
                if source_version!='' or re.search(r'\+b[0-9]+$',version):return result
                source,source_version=name,version
            if not package_name(source) or not isinstance(source_version,str) or not source_version:return result
            request={'package':{'ecosystem':'Debian:'+match[1],'name':source},'version':source_version}
        if not result['metadata_only']:
            try:advisories.validate_query(request);result['advisory_query']=request
            except advisories.AdvisoryError:return result
        result['metadata_profile']='package-manager-record' if result['metadata_only'] else 'distro-source-package'
        return result
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise PackageError() from None


def from_scanner(raw,observation):
    """Caller verifies image manifest/config; bind supplemental fields to its scan."""
    try:
        require(isinstance(raw,bytes) and len(raw)<=policy.MAX_DOCUMENT_BYTES
                and hashlib.sha256(raw).hexdigest()==observation['scanner_output_sha256'])
        document=policy.parse_document(raw);rows=document.get('artifacts')
        require(isinstance(rows,list) and 0<len(rows)<=images.MAX_PACKAGES)
        packages={}
        for row in rows:
            value=project(row);identity=value['package']['purl']
            require(identity not in packages or packages[identity]==value);packages[identity]=value
        return [packages[key] for key in sorted(packages)]
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):raise PackageError() from None
