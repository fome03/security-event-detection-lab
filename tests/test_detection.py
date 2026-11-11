import unittest
import tempfile
import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path
from src.detect_suspicious_logins import detect, load_events

BASE = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
def e(i, event='4625', user='alex', ip='192.0.2.10', host='LAB-PC-01'):
    return {'_time':BASE + timedelta(minutes=i),'event_id':event,'username':user,'source_ip':ip,'hostname':host}

class DetectionTests(unittest.TestCase):
    def test_repeated_failures_and_success(self):
        alerts=detect([e(i) for i in range(5)] + [e(5,'4624')])
        self.assertEqual([a['rule'] for a in alerts],['repeated_failed_logins','failed_logins_followed_by_success'])
    def test_no_false_alert_for_spaced_events(self):
        self.assertEqual(detect([e(i*20) for i in range(5)]),[])
    def test_no_cross_account_conflation(self):
        self.assertEqual(detect([e(i,user='alex' if i%2==0 else 'sam') for i in range(6)]),[])
    def test_success_without_failures_not_alert(self):
        self.assertEqual(detect([e(0,'4624')]),[])
    def test_out_of_order_input_normalized_by_loader(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'events.csv'
            with p.open('w',newline='') as f:
                w=csv.DictWriter(f,fieldnames=['timestamp','event_id','username','source_ip','hostname']);w.writeheader()
                for i in [3,2,1,0,4]:
                    w.writerow({'timestamp':(BASE+timedelta(minutes=i)).isoformat(),'event_id':'4625','username':'alex','source_ip':'192.0.2.10','hostname':'LAB-PC-01'})
            events=load_events(p)
            self.assertEqual(len(detect(events)),1)
    def test_invalid_naive_timestamp(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'bad.csv';p.write_text('timestamp,event_id,username,source_ip,hostname\n2026-11-10T12:00:00,4625,a,192.0.2.1,PC\n')
            with self.assertRaisesRegex(ValueError,'timezone'):
                load_events(p)

if __name__=='__main__':unittest.main()
