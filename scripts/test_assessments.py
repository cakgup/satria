"""Isolated integration checks; never reads production configuration or data."""
import base64
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
TEMP = tempfile.TemporaryDirectory(prefix='satria-assessment-test-')
os.environ.update(DATABASE_URL='sqlite:///' + str(Path(TEMP.name) / 'test.db').replace('\\', '/'),
                  REPORT_DIR=TEMP.name, SATRIA_DEMO_MODE='true', IRIS_URL='', IRIS_API_KEY='',
                  CELERY_BROKER_URL='memory://', CELERY_RESULT_BACKEND='cache+memory://')

from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal, engine
from app.models import Assessment, AssessmentFindingImage, Finding, ScanJob, TicketCase
from app.assessments import rating
from app.reporting import get_summary

VECTOR = 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'
IMAGE = {'name': 'QA.png', 'dataUrl': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl6Ju8AAAAASUVORK5CYII='}


class AssessmentTests(unittest.TestCase):
    def test_integrated_workflow(self):
        with TestClient(app) as c:
            self.assertEqual(c.get('/assessments/api/assets').status_code, 401)
            self.assertEqual(c.get('/assessments/api/evidence/1').status_code, 401)
            self.assertEqual(c.get('/assessments', follow_redirects=False).status_code, 303)
            c.post('/login', data={'username': 'assessment-tester'})
            asset = c.post('/api/assets', json={'name': 'Assessment QA', 'asset_type': 'web_application', 'target': 'https://example.test', 'criticality': 'high', 'environment': 'staging'}).json()
            self.assertIn('id', asset)
            prefix = '/assessments/api'
            self.assertEqual(c.post(prefix+'/assessments', json={'name': 'bad', 'assetId': 99999}).status_code, 400)
            self.assertEqual(c.post(prefix+'/assessments', json={'name': 'bad', 'assetId': asset['id']}, headers={'origin': 'https://unrelated.example'}).status_code, 403)
            created = c.post(prefix+'/assessments', json={'name': 'Manual QA', 'assetId': asset['id'], 'scope': 'Test scope'})
            self.assertEqual(created.status_code, 201, created.text)
            id = created.json()['assessment']['id']
            url = prefix+f'/assessments/{id}'
            self.assertEqual(c.get(url).json()['assessment']['target'], asset['target'])
            self.assertEqual(c.get(url).json()['assessment']['owner_name'], 'assessment-tester')
            result = {'testCode': 'OTG-INFO-001', 'status': 'Completed', 'remark': 'Checklist QA', 'evidenceImages': [IMAGE]}
            self.assertEqual(c.put(url+'/results', json=result).status_code, 200)
            detail = c.get(url).json()
            eid = detail['evidenceImages'][0]['id']
            self.assertEqual(c.get(prefix+f'/evidence/{eid}').headers['content-type'], 'image/png')
            result['evidenceImages'] = [{'id': eid}]
            self.assertEqual(c.put(url+'/results', json=result).status_code, 200)
            self.assertEqual(len(c.get(url).json()['results']), 1)
            report = {'title': 'Hardcoded key QA', 'cvssVector': VECTOR, 'cvssScore': 10,
                      'testCode': 'OTG-INFO-001', 'owaspCategories': ['A02:2021', 'A04:2021'],
                      'affectedPath': 'https://example.test/main.js\nLocal Storage',
                      'observation': 'Description\nTwo lines', 'impactDescription': 'Confidentiality loss',
                      'recommendation': 'Remediate', 'evidenceImages': [IMAGE]}
            created = c.post(url+'/findings', json=report)
            self.assertEqual(created.status_code, 201, created.text)
            fid = created.json()['finding']['id']
            finding_url = prefix+f'/findings/{fid}'
            finding = c.get(url).json()['findings'][0]
            self.assertEqual(finding['cvss_score'], '6.0')
            self.assertEqual(finding['severity'], 'Medium')
            feid = finding['evidenceImages'][0]['id']
            self.assertEqual(c.get(prefix+f'/finding-evidence/{feid}').status_code, 200)
            original = c.get(url).json()
            scope = 'Updated scope\nOnly approved endpoints <test>'
            self.assertEqual(c.patch(url+'/scope', json={'scope': scope}).status_code, 200)
            updated = c.get(url).json()
            self.assertEqual(updated['assessment']['scope'], scope)
            self.assertEqual(updated['findings'], original['findings'])
            self.assertEqual(updated['results'], original['results'])
            self.assertEqual(updated['evidenceImages'], original['evidenceImages'])
            for bad_scope in [{}, {'scope': None}, {'scope': 4}, {'scope': 'x'*20001}]:
                self.assertEqual(c.patch(url+'/scope', json=bad_scope).status_code, 400)
            self.assertEqual(c.get(url).json()['assessment']['scope'], scope)
            self.assertEqual(c.patch(url+'/scope', json={'scope': ''}).status_code, 200)
            self.assertEqual(c.get(url).json()['assessment']['scope'], '')
            self.assertEqual(c.patch(url+'/scope', json={'scope': scope}, headers={'origin': 'https://unrelated.example'}).status_code, 403)
            for bad in [{'cvssVector': VECTOR.replace('4.0', '3.1')}, {'cvssVector': 'CVSS:4.0/AV:N'}, {'owaspCategories': ['A02:2021', 'A02:2021']}, {'evidenceImages': [dict(IMAGE, dataUrl='data:image/png;base64,aGVsbG8=')]}]:
                self.assertEqual(c.put(finding_url, json={**report, **bad}).status_code, 400)
            self.assertEqual(c.get(url).json()['findings'][0]['title'], report['title'])
            other = c.post(prefix+'/assessments', json={'name': 'Other QA', 'assetId': asset['id']}).json()['assessment']['id']
            self.assertEqual(c.post(prefix+f'/assessments/{other}/findings', json={**report, 'evidenceImages': [{'id': feid}]}).status_code, 400)
            self.assertEqual(c.put(prefix+f'/assessments/{other}/results', json=result).status_code, 400)
            self.assertEqual(c.delete(prefix+f'/assessments/{other}').status_code, 200)
            report['title'] = 'Updated manual QA'
            report['evidenceImages'] = [{'id': feid}]
            self.assertEqual(c.put(finding_url, json=report).status_code, 200)
            data = c.get('/api/findings').json()
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]['id'], fid)
            self.assertEqual(data[0]['scanner'], 'manual-wstg')
            self.assertEqual(c.get('/api/scans').json(), [])
            self.assertIn('Updated manual QA', c.get('/findings?scanner=manual-wstg').text)
            self.assertIn('Buka laporan assessment', c.get(f'/findings/{fid}').text)
            exported = c.get('/reports/findings.csv')
            self.assertIn(VECTOR, exported.text)
            self.assertIn('Confidentiality loss', exported.text)
            self.assertEqual(c.get('/reports/findings.xlsx').status_code, 200)
            self.assertIn('Assessments', c.get('/assets').text)
            self.assertIn('/assessments/workspace', c.get('/assessments').text)
            self.assertIn('SATRIA Assessments', c.get('/assessments/workspace').text)
            with SessionLocal() as db:
                summary = get_summary(db)
                self.assertEqual(summary['findings'], 1)
                self.assertEqual(summary['scans'], 0)
                scan_id = db.get(Assessment, id).scan_job_id
                ticket = TicketCase(finding_id=fid, asset_id=asset['id'], title='Linked ticket QA')
                db.add(ticket)
                db.commit()
                ticket_id = ticket.id
            self.assertEqual(c.post(f'/scans/{scan_id}/rerun').status_code, 409)
            self.assertEqual(c.post(f'/scans/{scan_id}/delete').status_code, 409)
            self.assertEqual(c.delete(finding_url).status_code, 409)
            self.assertEqual(c.delete(url).status_code, 409)
            with SessionLocal() as db:
                self.assertIsNotNone(db.get(TicketCase, ticket_id))
                db.delete(db.get(TicketCase, ticket_id))
                db.commit()
            self.assertEqual(c.delete(url).status_code, 200)
            self.assertEqual(c.get(url).status_code, 404)
            self.assertEqual(c.get(prefix+f'/finding-evidence/{feid}').status_code, 404)
            self.assertEqual(c.get(prefix+f'/evidence/{eid}').status_code, 404)
            with SessionLocal() as db:
                self.assertEqual(db.query(Finding).count(), 0)
                self.assertEqual(db.query(ScanJob).count(), 0)
            c.post('/logout')
            self.assertEqual(c.get(prefix+'/assessments').status_code, 401)

    def test_cvss_known_scores(self):
        vectors = [
            ('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 9.3),
            ('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N', 0),
            (VECTOR, 6),
            ('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N/E:U/CR:L/IR:L/AR:L', 2.7),
        ]
        vectors.append(('CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N/E:U/CR:M/IR:H/MAV:N/MAC:L/MAT:P/MUI:A/MVC:L/MVI:H/MSC:N/MSI:N/MSA:L/S:P/AU:N/R:U', 1.7))
        for vector, expected in vectors:
            self.assertEqual(rating(vector)[1], expected)


if __name__ == '__main__':
    try:
        result = unittest.main(exit=False).result
    finally:
        engine.dispose()
        TEMP.cleanup()
    sys.exit(0 if result.wasSuccessful() else 1)
