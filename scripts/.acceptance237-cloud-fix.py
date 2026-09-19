from pathlib import Path

p = Path('api/action_scope.py')
s = p.read_text()
a = 'CIDR_RE = re.compile(r"(?<![\\w:])(?:\\d{1,3}\\.){3}\\d{1,3}/\\d{1,2}(?![\\w:])")\n'
b = a + '# These special cloud-service destinations are also denied by device_posture.\n# They are not all link-local: private-network permission must not admit them.\n_CLOUD_SERVICE_ADDRESSES = frozenset({\n    "169.254.169.254", "169.254.170.2", "100.100.100.200",\n    "168.63.129.16", "fd00:ec2::254",\n})\n'
assert s.count(a) == 1
s = s.replace(a, b)
a = '''    Lab environments admit everything local. A deployment that sets
    SHAKERSCAN_PRIVATE_NETWORK_TARGETS=allow (a self-hosted installation scanning its own
    intranet) admits loopback and private ranges for every environment; link-local, multicast,
    reserved and unspecified addresses stay refused because they are never a web application.
'''
b = '''    Lab environments admit local targets. A deployment that sets
    SHAKERSCAN_PRIVATE_NETWORK_TARGETS=allow also admits loopback/private targets in other
    environments. Special cloud-service destinations, link-local, multicast, unspecified
    addresses and the limited broadcast address remain denied regardless of that permission.
'''
assert s.count(a) == 1
s = s.replace(a, b)
a = '''        ip_obj.is_link_local
        or ip_obj.is_multicast'''
b = '''        str(ip_obj) in _CLOUD_SERVICE_ADDRESSES
        or ip_obj.is_link_local
        or ip_obj.is_multicast'''
assert s.count(a) == 1
p.write_text(s.replace(a, b))
p = Path('tests/test_schedule_numeric_target.py')
s = p.read_text()
a = '["169.254.169.254", "::ffff:169.254.169.254", "0.0.0.0", "::", "224.0.0.1", "fe80::1"]'
b = '["169.254.169.254", "::ffff:169.254.169.254", "0.0.0.0", "::", "224.0.0.1", "fe80::1", "fd00:ec2::254", "100.100.100.200", "168.63.129.16", "::ffff:100.100.100.200"]'
assert s.count(a) == 1
p.write_text(s.replace(a, b))
