from unittest import TestCase

from rfw import cmdparse, timeutil, iptables, iputil
from rfw.iptables import Rule, Chain, Iptables

class CmdParseTest(TestCase):

    def test_parse_command(self):
        self.assertEqual( 
                cmdparse.parse_command_path('/rule/',
                                            """{ "target": "DROP", "inp": "eth0", 
                                            "chain": "INPUT", "source": "5.6.7.8",
                                            "destination": "0.0.0.0/0"}"""), 
            ('rule', Rule(chain='INPUT', num=None, pkts=None, bytes=None, target='DROP', prot='all', opt='--', inp='eth0', out='*', source='5.6.7.8', destination='0.0.0.0/0', sport=None, dport=None)))
        self.assertEqual( 
                cmdparse.parse_command_path('/chain/chain0',
                                            """{ "name": "chain0" }"""), 
            ('chain', Chain("chain0")))



class IpUtilTest(TestCase):

    def test_ip2long(self):
        self.assertEqual(iputil.ip2long('1.2.3.4'), 16909060)
        self.assertEqual(iputil.ip2long('1.2.3.250'), 16909306)
        self.assertEqual(iputil.ip2long('250.2.3.4'), 4194435844)
        self.assertEqual(iputil.ip2long('129.2.3.129'), 2164392833)

    def test_cidr2range(self):
        self.assertEqual(iputil.cidr2range('1.2.3.4'), (16909060, 16909060))
        self.assertEqual(iputil.cidr2range('1.2.3.4/32'), (16909060, 16909060))
        self.assertEqual(iputil.cidr2range('1.2.3.4/31'), (16909060, 16909061))
        self.assertEqual(iputil.cidr2range('1.2.3.4/30'), (16909060, 16909063))
        self.assertEqual(iputil.cidr2range('1.2.3.4/0'), (0, 4294967295))
        self.assertEqual(iputil.cidr2range('129.2.3.129/28'), (2164392832, 2164392847))

    def test_ip_in_list(self):
        self.assertEqual(iputil.ip_in_list('1.2.0.0/16', ['1.2.3.4']), True)



#TODO extract reusable libraries along with testcases
class TimeUtilTest(TestCase):
    
    def test_parse_interval(self):
        self.assertEqual( timeutil.parse_interval('350'), 350 )
        self.assertEqual( timeutil.parse_interval('20000s'), 20000 )
        self.assertEqual( timeutil.parse_interval('10m'), 600 )
        self.assertEqual( timeutil.parse_interval('2h'), 7200 )
        self.assertEqual( timeutil.parse_interval('10d'), 864000 )
        self.assertEqual( timeutil.parse_interval('0'), 0 )
        self.assertEqual( timeutil.parse_interval('0m'), 0 )
        self.assertEqual( timeutil.parse_interval('-3'), None )
        self.assertEqual( timeutil.parse_interval('10u'), None )
        self.assertEqual( timeutil.parse_interval('abc'), None )
        self.assertEqual( timeutil.parse_interval(''), None )


class StateTest(TestCase):

    def test_find(self):
        r1 = Rule(chain='INPUT', num='9', pkts='0', bytes='0', target='DROP', prot='all', opt='--', inp='eth+', out='*', source='2.2.2.2', destination='0.0.0.0/0', sport=None, dport=None)
        r2 = Rule(chain='INPUT', num='10', pkts='0', bytes='0', target='ACCEPT', prot='tcp', opt='--', inp='*', out='*', source='3.4.5.6', destination='0.0.0.0/0', sport='12345', dport=None)
        r3 = Rule(chain='INPUT', num='1', pkts='14', bytes='840', target='DROP', prot='tcp', opt='--', inp='*', out='*', source='0.0.0.0/0', destination='0.0.0.0/0', sport=None, dport='ssh')
        r4 = Rule(chain='OUTPUT', num='1', pkts='0', bytes='0', target='DROP', prot='all', opt='--', inp='*', out='tun+', source='0.0.0.0/0', destination='7.7.7.6', sport=None, dport=None)
        rules = set([r1, r2, r3, r4])
        d = {}
        for r in rules:
            d.setdefault(r.chain, set()).add(r)
        inst1 = iptables.State(d)
        self.assertEqual( inst1.find({}), rules)
        self.assertEqual( inst1.find({'destination': ['0.0.0.0/0']}), set([r1, r2, r3]))
        self.assertEqual( inst1.find({'target': ['ACCEPT']}), set([r2]))
        self.assertEqual( inst1.find({'chain': ['OUTPUT']}), set([r4]))
        self.assertEqual( inst1.find({'chain': ['OUTPUT'], 'target':['ACCEPT']}), set())
        self.assertEqual( inst1.find({'chain': ['OUTPUT', 'INPUT'], 'target':['ACCEPT']}), set([r2]))
        self.assertEqual( inst1.find({'chain': ['OUTPUT', 'INPUT'], 'target':['ACCEPT', 'DROP']}), rules)
        self.assertEqual( inst1.find({'chain': ['OUTPUT', 'INPUT'], 'target':['DROP'], 'dport': ['ssh']}), set([r3]))
        self.assertEqual( inst1.find({'chain': ['INPUT'], 'sport': ['12345']}), set([r2]))
        
    def test_create_rule(self):
        """Test creating Rule objects in various ways
        """
        r1 = Rule({'chain': 'INPUT', 'source': '1.2.3.4'})
        self.assertEquals(str(r1), "Rule(chain='INPUT', num=None, pkts=None, bytes=None, target=None, prot='all', opt='--', inp='*', out='*', source='1.2.3.4', destination='0.0.0.0/0', sport=None, dport=None)")
        r2 = Rule(chain='INPUT', num=None, pkts=None, bytes=None, target=None, prot='all', opt='--', inp='*', out='*', source='1.2.3.4', destination='0.0.0.0/0', sport=None, dport=None)
        self.assertEquals(str(r2), "Rule(chain='INPUT', num=None, pkts=None, bytes=None, target=None, prot='all', opt='--', inp='*', out='*', source='1.2.3.4', destination='0.0.0.0/0', sport=None, dport=None)")
        r3 = Rule(['INPUT', None, None, None, None, 'all', '--', '*', '*', '1.2.3.4', '0.0.0.0/0', None, 'ssh'])
        self.assertEquals(str(r3), "Rule(chain='INPUT', num=None, pkts=None, bytes=None, target=None, prot='all', opt='--', inp='*', out='*', source='1.2.3.4', destination='0.0.0.0/0', sport=None, dport='ssh')")


class IptablesTest(TestCase):
    def test_parse(self):
        b = """Chain INPUT (policy ACCEPT 113726 packets, 92068876 bytes)
num      pkts      bytes target     prot opt in     out     source               destination         
1           3      376 ACCEPT     tcp  --  *      *       127.0.0.1            0.0.0.0/0            tcp dpt:7393
2           0        0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:7393
3           0        0 f2b-test   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
num      pkts      bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 75425 packets, 4867854 bytes)
num      pkts      bytes target     prot opt in     out     source               destination         
1           3      164 ACCEPT     tcp  --  *      *       0.0.0.0/0            127.0.0.1            tcp spt:7393
2           0        0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:7393

Chain f2b-test (1 references)
num      pkts      bytes target     prot opt in     out     source               destination         
1           0        0 REJECT     all  --  *      *       1.2.3.4              0.0.0.0/0            reject-with icmp-port-unreachable
2           0        0 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0           
"""
        r = Iptables.parse_iptables(b)
        self.assertEquals(r['INPUT'], set([
            Rule(chain='INPUT', num='1', pkts='3', bytes='376', target='ACCEPT', prot='tcp', opt='--', inp='*', out='*', source='127.0.0.1', destination='0.0.0.0/0', sport=None, dport='7393'),
            Rule(chain='INPUT', num='2', pkts='0', bytes='0', target='DROP', prot='tcp', opt='--', inp='*', out='*', source='0.0.0.0/0', destination='0.0.0.0/0', sport=None, dport='7393'),
            Rule(chain='INPUT', num='3', pkts='0', bytes='0', target='f2b-test', prot='tcp', opt='--', inp='*', out='*', source='0.0.0.0/0', destination='0.0.0.0/0', sport=None, dport='22')]))
