#!/usr/bin/env python3
"""Go tool license sources must match binary-recorded module content, not labels."""
import base64
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import warnings
from unittest.mock import Mock,patch
import zipfile

import dependency_tool_sources as sources

NAME='example.org/library'
VERSION='v1.2.3'


def archive(entries=None):
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED) as result:
        for name,raw in entries or [(NAME+'@'+VERSION+'/LICENSE',b'license text'),(NAME+'@'+VERSION+'/data',b'data')]:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore',UserWarning)
                result.writestr(name,raw)
    return output.getvalue()


def expected():
    lines=''.join(hashlib.sha256(raw).hexdigest()+'  '+NAME+'@'+VERSION+'/'+name+'\n'
                  for name,raw in [('LICENSE',b'license text'),('data',b'data')])
    return 'h1:'+base64.b64encode(hashlib.sha256(lines.encode()).digest()).decode()


class SourceTests(unittest.TestCase):
    def test_zip_h1_matches_go_hash1_and_ignores_compression_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);path=root/'module.zip';path.write_bytes(archive())
            result=sources.observe_zip(root,path,NAME,VERSION,expected())
            self.assertEqual(result['sum'],expected());self.assertEqual(result['files'][0]['content'],b'license text')
            self.assertEqual(result['files'][0]['file'],'LICENSE')
            changed=archive([(NAME+'@'+VERSION+'/data',b'data'),(NAME+'@'+VERSION+'/LICENSE',b'license text')])
            path.write_bytes(changed)
            self.assertEqual(sources.observe_zip(root,path,NAME,VERSION,expected())['sum'],expected())

    def test_wrong_digest_duplicate_unsafe_or_foreign_entries_never_supply_licenses(self):
        for entries in [[(NAME+'@'+VERSION+'/LICENSE',b'changed')],
                        [(NAME+'@'+VERSION+'/../LICENSE',b'x')],
                        [('PRIVATE_CANARY/LICENSE',b'x')],
                        [(NAME+'@'+VERSION+'/LICENSE',b'x'),(NAME+'@'+VERSION+'/LICENSE',b'y')],
                        [(NAME+'@'+VERSION+'/new\nline',b'x')]]:
            with self.subTest(entries=entries),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);path=root/'module.zip';path.write_bytes(archive(entries))
                with self.assertRaises(sources.ToolSourceError) as error:sources.observe_zip(root,path,NAME,VERSION,expected())
                self.assertNotIn('CANARY',str(error.exception))

    def test_expanded_entry_and_compressed_budgets_apply_before_license_use(self):
        for limit in ['MAX_ENTRIES','MAX_ZIP_BYTES','MAX_EXPANDED_BYTES']:
            with self.subTest(limit=limit),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);path=root/'module.zip';path.write_bytes(archive())
                with patch.object(sources,limit,1),self.assertRaises(sources.ToolSourceError):
                    sources.observe_zip(root,path,NAME,VERSION,expected())

    def test_symlink_sources_and_license_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);target=root/'target';target.write_bytes(archive());link=root/'module.zip';link.symlink_to(target)
            with self.assertRaises(sources.ToolSourceError):sources.observe_zip(root,link,NAME,VERSION,expected())
            output=io.BytesIO()
            with zipfile.ZipFile(output,'w') as result:
                info=zipfile.ZipInfo(NAME+'@'+VERSION+'/LICENSE');info.external_attr=(0o120777<<16)
                result.writestr(info,b'../PRIVATE_CANARY')
            target.write_bytes(output.getvalue())
            with self.assertRaises(sources.ToolSourceError):sources.observe_zip(root,target,NAME,VERSION,expected())

    def test_corrupt_deflate_stream_fails_with_the_safe_source_error(self):
        raw=bytearray(archive())
        with zipfile.ZipFile(io.BytesIO(raw)) as reader:
            entry=reader.infolist()[0]
            offset=entry.header_offset+30+len(entry.filename.encode())+len(entry.extra)
        raw[offset]=7  # Reserved DEFLATE block type; central directory remains parseable.
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);path=root/'module.zip';path.write_bytes(raw)
            with self.assertRaises(sources.ToolSourceError):sources.observe_zip(root,path,NAME,VERSION,expected())

    def test_public_download_is_credential_free_content_bound_and_classifier_receipted(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);cache=root/'cache';cache.mkdir();path=cache/'download.zip';path.write_bytes(archive())
            classifier=Mock();classifier.receipt={'trusted_base':'a'*40};classifier.classify.return_value={
                hashlib.sha256(b'license text').hexdigest():{'license':'MIT','status':'candidate','coverage_percent':100,
                    'ids':['MIT'],'sha256':hashlib.sha256(b'license text').hexdigest()}}
            calls=[]
            def run(arguments,work,environment,**_options):
                calls.append(arguments);self.assertNotIn('GH_TOKEN',environment)
                self.assertEqual(environment['GOVCS'],'*:off');self.assertEqual(environment['GOAUTH'],'off')
                if arguments==['go','env','GOMODCACHE']:return str(cache).encode()
                self.assertEqual(arguments,['go','mod','download','-json',NAME+'@'+VERSION])
                return json.dumps({'Path':NAME,'Version':VERSION,'Sum':expected(),'GoModSum':expected(),'Zip':str(path)}).encode()
            with patch.object(sources.inventory,'_run',side_effect=run):
                client=sources.Sources(root,{'PATH':'/usr/bin','GH_TOKEN':'PRIVATE_CANARY'},classifier)
                result=client.resolve(NAME,VERSION,expected())
                self.assertEqual(client.resolve(NAME,VERSION,expected()),result)
            self.assertEqual(result['license'],'MIT');self.assertEqual(result['source']['sum'],expected())
            self.assertEqual(result['source']['verification'],'go-module-zip-h1')
            self.assertNotIn('CANARY',json.dumps(result));self.assertNotIn(str(root),json.dumps(result))
            self.assertEqual(len(calls),2);self.assertEqual(classifier.classify.call_count,1)

    def test_download_identity_sum_and_source_failures_cannot_reach_classifier(self):
        for field,value in [('Path','example.org/wrong'),('Version','v9.0.0'),('Sum',None),('Replace',{}),('Error','PRIVATE_CANARY')]:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);classifier=Mock();cache=root/'cache';cache.mkdir();path=cache/'download.zip';path.write_bytes(archive())
                record={'Path':NAME,'Version':VERSION,'Sum':expected(),'GoModSum':expected(),'Zip':str(path),field:value}
                def run(arguments,*_args,**_kwargs):
                    return str(cache).encode() if arguments==['go','env','GOMODCACHE'] else json.dumps(record).encode()
                with patch.object(sources.inventory,'_run',side_effect=run),self.assertRaises(sources.ToolSourceError):
                    sources.Sources(root,{},classifier).resolve(NAME,VERSION,expected())
                classifier.classify.assert_not_called()

    def test_only_exact_go_toolchain_sources_can_use_fresh_sumdb_instead_of_binary_sum(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);classifier=Mock();classifier.classify.return_value={}
            name='golang.org/toolchain';version='v0.0.1-go1.27.1.linux-amd64'
            filename=name+'@'+version+'/src/data';raw=b'data'
            checksum='h1:'+base64.b64encode(hashlib.sha256((hashlib.sha256(raw).hexdigest()+'  '+filename+'\n').encode()).digest()).decode()
            client=sources.Sources(root,{'GOMODCACHE':'/PRIVATE_CANARY'},classifier)
            def run(arguments,_work,environment,**_options):
                self.assertEqual(environment['GOSUMDB'],'sum.golang.org');self.assertEqual(environment['GOTOOLCHAIN'],'local')
                self.assertTrue(Path(environment['GOMODCACHE']).is_relative_to(client.work))
                if arguments==['go','env','GOMODCACHE']:return environment['GOMODCACHE'].encode()
                cache=Path(environment['GOMODCACHE']);cache.mkdir();path=cache/'source.zip';path.write_bytes(archive([(filename,raw)]))
                return json.dumps({'Path':name,'Version':version,'Sum':checksum,'Zip':str(path)}).encode()
            with patch.object(sources.inventory,'_run',side_effect=run) as tool:
                for invalid in [(NAME,VERSION), (name,'v0.0.1-go1.27.1.windows-amd64')]:
                    with self.assertRaises(sources.ToolSourceError):client.resolve(*invalid,None)
                tool.assert_not_called()
                result=client.resolve(name,version,None)
            self.assertEqual(result['source']['checksum_binding'],'fresh-sumdb-toolchain')
            self.assertEqual(result['source']['sum'],checksum);self.assertIsNone(result['license'])


if __name__=='__main__':unittest.main()
