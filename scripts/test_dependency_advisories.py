#!/usr/bin/env python3
"""Advisory absence requires a complete exact-version provider observation."""
import copy
from datetime import datetime
import io
import json
import unittest
from unittest.mock import patch

import dependency_advisories as advisories

GHSA='GHSA-aaaa-bbbb-cccc'
COMPONENT={'ecosystem':'npm','name':'lodash','version':'4.17.11'}


def record(**changes):
    return {'id':GHSA,'modified':'2026-10-20T00:00:00Z','aliases':['CVE-2020-12345'],
            'affected':[{'package':{'ecosystem':'npm','name':'lodash'}}],
            'database_specific':{'severity':'HIGH'},'summary':'PRIVATE_CANARY',**changes}


class AdvisoryTests(unittest.TestCase):
    def test_complete_paginated_query_binds_exact_coordinates_and_omits_provider_prose(self):
        client=advisories.Client();second=record(id='CVE-2020-12345',aliases=[],database_specific={})
        pages=[{'vulns':[record()],'next_page_token':'opaque-token'},{'vulns':[second]}]
        with patch.object(client,'request',side_effect=pages) as request:
            result=client.observe(COMPONENT)
        self.assertEqual(result['status'],'observed');self.assertEqual(result['component'],COMPONENT)
        self.assertIsNotNone(datetime.fromisoformat(result['observed_at']).tzinfo)
        self.assertEqual(result['vulnerabilities'],[{'id':'CVE-2020-12345','severity':'unknown'},{'id':GHSA,'severity':'high'}])
        self.assertEqual(request.call_args_list[0].args[0],{'package':{'ecosystem':'npm','name':'lodash'},'version':'4.17.11'})
        self.assertEqual(request.call_args_list[1].args[0]['page_token'],'opaque-token')
        self.assertNotIn('CANARY',json.dumps(result))

    def test_empty_complete_query_is_observed_but_failures_and_unsupported_scopes_are_not_empty(self):
        client=advisories.Client()
        with patch.object(client,'request',return_value={}):result=client.observe(COMPONENT)
        self.assertEqual(result['status'],'observed');self.assertEqual(result['vulnerabilities'],[])
        for ecosystem in ['fixture','generic','github-actions','docker']:
            with self.subTest(ecosystem=ecosystem),patch.object(client,'request') as request:
                result=client.observe({**COMPONENT,'ecosystem':ecosystem})
            self.assertEqual(result['status'],'unsupported');self.assertIsNone(result['vulnerabilities']);request.assert_not_called()
        client=advisories.Client()
        with patch.object(client,'request',side_effect=advisories.AdvisoryError()):result=client.observe(COMPONENT)
        self.assertEqual(result['status'],'unavailable');self.assertIsNone(result['vulnerabilities'])

    def test_malformed_incomplete_or_unmapped_records_never_become_clean(self):
        for page in [{'vulns':None},{'vulns':[record(affected=[])]},
                     {'vulns':[record(id='PYSEC-2020-1',aliases=[])]},
                     {'vulns':[record(affected=[{'package':{'ecosystem':'npm','name':'other'}}])]},
                     {'vulns':[record(),record()]},{'error':'PRIVATE_CANARY'},
                     {'vulns':[record(withdrawn='PRIVATE_CANARY')]}]:
            with self.subTest(page=page),patch.object(advisories.Client,'request',return_value=page):
                result=advisories.Client().observe(COMPONENT)
            self.assertEqual(result['status'],'unavailable');self.assertIsNone(result['vulnerabilities']);self.assertNotIn('CANARY',json.dumps(result))
        client=advisories.Client()
        with patch.object(client,'request',return_value={'next_page_token':'same'}):result=client.observe(COMPONENT)
        self.assertEqual(result['status'],'unavailable')

    def test_missing_conflicting_or_unknown_severity_is_conservative_and_withdrawals_are_explicit(self):
        for severity in [None,'PRIVATE_CANARY','CRITICAL','MODERATE']:
            value=record(database_specific={'severity':severity})
            with patch.object(advisories.Client,'request',return_value={'vulns':[value]}):result=advisories.Client().observe(COMPONENT)
            expected={'CRITICAL':'critical','MODERATE':'moderate'}.get(severity,'unknown')
            self.assertEqual(result['vulnerabilities'][0]['severity'],expected)
        value=record();value['affected'][0]['ecosystem_specific']={'severity':'CRITICAL'}
        with patch.object(advisories.Client,'request',return_value={'vulns':[value]}):result=advisories.Client().observe(COMPONENT)
        self.assertEqual(result['vulnerabilities'][0]['severity'],'critical')
        value=record(withdrawn='2026-10-21T00:00:00Z')
        with patch.object(advisories.Client,'request',return_value={'vulns':[value]}):result=advisories.Client().observe(COMPONENT)
        self.assertEqual(result['vulnerabilities'],[]);self.assertEqual(result['withdrawn'],[GHSA])

    def test_python_name_normalization_go_pins_and_cache_isolation(self):
        self.assertEqual(advisories.query({'ecosystem':'pypi','name':'Py_YAML','version':'6.0.3'}),
                         {'package':{'ecosystem':'PyPI','name':'py-yaml'},'version':'6.0.3'})
        self.assertEqual(advisories.query({'ecosystem':'gomod','name':'example.org/pkg','version':'v1.2.3'})['version'],'v1.2.3')
        for value in [{**COMPONENT,'version':'latest'},{**COMPONENT,'name':'../PRIVATE_CANARY'},
                      {'ecosystem':'gomod','name':'example.org/pkg','version':'1.2.3'}]:
            with self.subTest(value=value),self.assertRaises(advisories.AdvisoryError):advisories.query(value)
        client=advisories.Client()
        with patch.object(client,'request',return_value={}) as request:
            result=client.observe(COMPONENT);result['vulnerabilities'].append({'tampered':True})
            self.assertEqual(client.observe(COMPONENT)['vulnerabilities'],[])
        self.assertEqual(request.call_count,1)


class Response(io.BytesIO):
    status=200
    def __init__(self,raw=b'{}',headers=None):super().__init__(raw);self.headers={} if headers is None else headers
    def geturl(self):return advisories.ENDPOINT


class TransportTests(unittest.TestCase):
    def test_fixed_post_has_no_authentication_redirect_or_proxy_inheritance(self):
        client=advisories.Client();opener=unittest.mock.Mock();opener.open.return_value=Response()
        with patch.object(advisories.urllib.request,'build_opener',return_value=opener) as create:
            self.assertEqual(client.request(advisories.query(COMPONENT)),{})
        request=opener.open.call_args.args[0]
        self.assertEqual(request.full_url,advisories.ENDPOINT);self.assertEqual(request.get_method(),'POST')
        self.assertNotIn('Authorization',dict(request.header_items()))
        self.assertEqual(create.call_args.args[0].proxies,{})
        with self.assertRaises(advisories.AdvisoryError):create.call_args.args[1].redirect_request(None,None,None,None,None,None)
        self.assertEqual(len(client.receipts),1);self.assertNotIn('lodash',json.dumps(client.receipts))

    def test_budgets_truncation_encoding_duplicate_json_and_input_shape_are_rejected(self):
        for response in [Response(b'{"vulns":[],"vulns":[]}'),Response(b'NaN'),Response(b'{}',{'Content-Length':'3'}),
                         Response(b'{}',{'Content-Encoding':'gzip'}),Response(b'{}',{'Content-Length':'True'})]:
            opener=unittest.mock.Mock();opener.open.return_value=response
            with self.subTest(response=response),patch.object(advisories.urllib.request,'build_opener',return_value=opener), \
                 self.assertRaises(advisories.AdvisoryError):advisories.Client().request(advisories.query(COMPONENT))
        for budget in ['MAX_REQUESTS','MAX_RESPONSE_BYTES','MAX_TOTAL_BYTES']:
            opener=unittest.mock.Mock();opener.open.return_value=Response()
            with self.subTest(budget=budget),patch.object(advisories,budget,0), \
                 patch.object(advisories.urllib.request,'build_opener',return_value=opener),self.assertRaises(advisories.AdvisoryError):
                advisories.Client().request(advisories.query(COMPONENT))
        with self.assertRaises(advisories.AdvisoryError):advisories.Client().request({'url':'https://PRIVATE_CANARY'})


if __name__=='__main__':unittest.main()
