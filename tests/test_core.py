import unittest
from netwatch.core import Packet, aggregate, flag_windows


def packet(t=0,port=443,host='192.0.2.1',size=100):
    return Packet(t,host,'198.51.100.1',50000,port,'TCP',size)


class AggregationTests(unittest.TestCase):
    def test_half_open_windows(self):
        rows=aggregate([packet(5),packet(4.999),packet(0)])
        self.assertEqual([r['packet_count'] for r in rows],[2,1])
        self.assertEqual(rows[0]['byte_count'],200)
        self.assertEqual(rows[0]['mean_interarrival'],4.999)

    def test_host_isolation_and_unique_flows(self):
        rows=aggregate([packet(),packet(1),packet(2,host='192.0.2.2')])
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[0]['flow_count'],1)
        self.assertEqual(rows[0]['packets_per_second'],0.4)

    def test_empty(self):
        self.assertEqual(aggregate([]),[])

    def test_invalid_inputs(self):
        for t in [-1,float('nan'),float('inf')]:
            with self.assertRaises(ValueError): packet(t)
        for w in [0,-1,float('nan'),float('inf')]:
            with self.assertRaises(ValueError): aggregate([],w)
        with self.assertRaises(ValueError): packet(port=65536)
        with self.assertRaises(ValueError): packet(size=-1)

    def test_threshold_boundary(self):
        rows=aggregate([packet(port=i) for i in range(21)])
        self.assertTrue(list(flag_windows(rows))[0]['is_anomaly'])
        self.assertFalse(list(flag_windows(rows,max_ports=21))[0]['is_anomaly'])

    def test_no_empty_windows_invented(self):
        rows=aggregate([packet(0),packet(100)])
        self.assertEqual([r['window_start'] for r in rows],[0,100])

if __name__=='__main__': unittest.main()
