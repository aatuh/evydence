#!/usr/bin/env python3
"""Maintenance review signals, unknown states and input-bound reporting."""
from datetime import datetime, timedelta, timezone
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import dependency_maintenance as maintenance
import dependency_reports as reports

NOW=datetime(2026,10,22,tzinfo=timezone.utc)


def component():
    return {'ecosystem':'gomod','name':'github.com/example/library','version':'v1.2.3',
            'version_published_at':None,'origins':['application'],'source':{'verification':'go-mod-verify'}}


def metadata():
    return {'metadata_status':'inventory-version','repository':'example/library','version_timestamp':None,
            'deprecated':None,'source_commit':None,'release_tag':None}


def repository():
    return {'metadata_status':'observed','canonical_repository':'example/library','archived':False,'disabled':False,
            'last_push':NOW.isoformat(),'commits':{},'releases':{}}


class SignalTests(unittest.TestCase):
    def test_age_boundaries_archived_disabled_and_deprecation_are_separate_review_signals(self):
        row=component(); meta=metadata(); repo=repository()
        meta.update(version_timestamp=(NOW-timedelta(days=365)).isoformat(),deprecated=True)
        repo.update(archived=True,disabled=True,last_push=(NOW-timedelta(days=730)).isoformat())
        result=maintenance.review(row,meta,repo,NOW)
        self.assertEqual(result['review_signals'],['package-deprecated','repository-archived','repository-disabled',
                         'repository-no-push-730-days','selected-version-365-days-old'])
        self.assertEqual(result['status'],'review')
        self.assertNotIn('unmaintained',json.dumps(result))
        meta.update(version_timestamp=(NOW-timedelta(days=364)).isoformat(),deprecated=False)
        repo=repository(); repo['last_push']=(NOW-timedelta(days=729)).isoformat()
        result=maintenance.review(row,meta,repo,NOW)
        self.assertEqual(result['review_signals'],[])
        self.assertEqual(result['status'],'no-listed-signal')

    def test_missing_dates_unmapped_and_unavailable_repositories_stay_unknown(self):
        meta=metadata(); meta['repository']=None
        result=maintenance.review(component(),meta,None,NOW)
        self.assertEqual(result['status'],'unknown')
        self.assertEqual(result['metadata_gaps'],['repository-unmapped','version-timestamp-unavailable'])
        meta=metadata()
        result=maintenance.review(component(),meta,{'metadata_status':'not-found'},NOW)
        self.assertIn('repository-not-found',result['metadata_gaps'])
        meta['version_timestamp']=(NOW+timedelta(days=5)).isoformat()
        result=maintenance.review(component(),meta,repository(),NOW)
        self.assertIn('timestamp-in-future',result['review_signals'])
        self.assertIsNone(result['selected_version_age_days'])

    def test_fixture_source_time_is_not_reported_as_payload_version_release_time(self):
        row=component(); row.update(ecosystem='fixture',version='a'*64)
        meta=metadata(); meta['source_commit']='b'*40
        repo=repository(); repo['commits']={'b'*40:'2020-01-01T00:00:00Z'}
        result=maintenance.review(row,meta,repo,NOW)
        self.assertIsNone(result['selected_version_timestamp'])
        self.assertEqual(result['source_commit_timestamp'],'2020-01-01T00:00:00Z')
        self.assertNotIn('selected-version-365-days-old',result['review_signals'])
        self.assertNotIn('version-timestamp-unavailable',result['metadata_gaps'])

    def test_unsafe_dates_or_coordinates_fail_without_echoing_private_content(self):
        for field,value in [('name','SECRET_CANARY\nname'),('version','bad\nversion')]:
            row=component(); row[field]=value
            with self.subTest(field=field), self.assertRaises(maintenance.MaintenanceError) as error:
                maintenance.review(row,metadata(),repository(),NOW)
            self.assertNotIn('CANARY',str(error.exception))
        for value in ['yesterday','2026-10-22','2026-10-22T00:00:00']:
            meta=metadata(); meta['version_timestamp']=value
            with self.subTest(value=value), self.assertRaises(maintenance.MaintenanceError):
                maintenance.review(component(),meta,repository(),NOW)


class CollectionTests(unittest.TestCase):
    def test_archive_release_tag_comes_from_pinned_url_instead_of_display_version(self):
        row={'ecosystem':'generic','name':'oasdiff','version':'1.29.1','origins':['qa-tool'],
             'source':{'url':'https://github.com/oasdiff/oasdiff/releases/download/v1.29.1/oasdiff_1.29.1_linux_amd64.tar.gz'}}
        result=maintenance.metadata([row])[('generic','oasdiff','1.29.1')]
        self.assertEqual(result['release_tag'],'v1.29.1')
        row['source']['url']=row['source']['url'].replace('/v1.29.1/','/unrelated/')
        with self.assertRaises(maintenance.MaintenanceError): maintenance.metadata([row])

    def test_generation_freezes_sources_and_covers_every_component_with_deduplicated_queries(self):
        components=[{**component(),'version_published_at':NOW.isoformat()},
                    {**component(),'version':'v1.3.0','version_published_at':NOW.isoformat()}]
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); (root/'input').write_bytes(b'input')
            with patch.object(maintenance,'inputs',return_value=(components,[],{'input':b'input'})), \
                 patch.object(maintenance.sources,'repositories',return_value={'example/library':repository()}) as query:
                result=maintenance.collect(root,NOW)
                self.assertEqual(len(result['components']),2)
                self.assertEqual(len(query.call_args.args[0]),1)
                self.assertEqual(result['inputs'],{'input':hashlib.sha256(b'input').hexdigest()})
                maintenance.check(root,result)
                changed=copy.deepcopy(result); changed['components'].pop()
                with self.assertRaises(maintenance.MaintenanceError): maintenance.check(root,changed)
                def mutate(_requests):
                    (root/'input').write_bytes(b'owner edit'); return {'example/library':repository()}
                query.side_effect=mutate
                with self.assertRaises(maintenance.MaintenanceError): maintenance.collect(root,NOW)
                self.assertEqual((root/'input').read_bytes(),b'owner edit')


class WriterTests(unittest.TestCase):
    def test_schema_atomic_overwrite_symlink_and_owner_file_preservation(self):
        schema='evydence-dependency-maintenance.v1'; document={'schema':schema,'components':[]}
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); target=root/'report.json'
            reports.write(root,'report.json',document,schema)
            before=target.read_bytes()
            with self.assertRaises(reports.ReportError): reports.write(root,'report.json',document,schema)
            reports.write(root,'report.json',document,schema,replace=True)
            self.assertEqual(target.read_bytes(),before)
            preflight=target.stat(); target.write_text(json.dumps({**document,'owner_edit':True}))
            with self.assertRaises(reports.ReportError):
                reports.write(root,'report.json',document,schema,replace=True,expected=preflight)
            self.assertTrue(json.loads(target.read_bytes())['owner_edit'])
            target.write_text('owner data')
            (root/'link').symlink_to(target); (root/'dir-link').symlink_to(root,target_is_directory=True)
            for name in ['report.json','link','dir-link/new.json','../escape.json',str(target)]:
                with self.subTest(name=name), self.assertRaises(reports.ReportError): reports.write(root,name,document,schema,replace=True)
            self.assertEqual(target.read_text(),'owner data')
            owned=root/'.dependency-report-fixed'; owned.write_text('owner temporary file')
            with patch.object(reports.uuid,'uuid4') as identifier:
                identifier.return_value.hex='fixed'
                with self.assertRaises(reports.ReportError): reports.write(root,'new.json',document,schema)
            self.assertEqual(owned.read_text(),'owner temporary file')


if __name__=='__main__': unittest.main()
