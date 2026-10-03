"""Bounded SNMPv3 discovery through installed Nmap and its reviewed snmp-info script."""
import ipaddress
from runtime.models import PreparedCommand,PreparedExecution
from .network_inputs import CapabilityInputError,_addresses,_require_network_policy
from .nse import NseCheckAdapter


class SnmpInspectAdapter(NseCheckAdapter):
    capability_name='service.snmp.inspect'
    adapter_name='nmap'
    adapter_version='1'

    def prepare(self, *, target, args, policy):
        _require_network_policy(policy)
        if set(args)-{'port'}:
            raise CapabilityInputError('SNMP inspection accepts only the target service port')
        port=args.get('port',161)
        if type(port) is not int or not 1<=port<=65535:
            raise CapabilityInputError('SNMP port must be from 1 to 65535')
        addresses=_addresses(target)
        commands=tuple(PreparedCommand('nmap',
            (('-6',) if ipaddress.ip_address(address).version==6 else ())+
            ('-sU','-Pn','-n','--max-retries','0','--max-parallelism','1',
             '--host-timeout','30s','--script-timeout','15s','-p',str(port),
             '--script','+snmp-info','--script-args','snmp.retries=0,snmp.timeout=2000',
             '-oX','-',address),address) for address in addresses)
        values={'approved_addresses':list(addresses),'ports':[port],'scripts':['snmp-info'],
                'transport':'udp','credential_use':False,'proof_state':'observation_only'}
        budget={'hosts_attempted':len(addresses),'udp_ports_attempted':len(addresses),
                'tool_wall_seconds':30*len(addresses)}
        if target.target_kind=='device':
            budget['device_fragility_points']=10*len(addresses)
        return PreparedExecution(self.capability_name,self.adapter_name,'1',commands,budget,
            PreparedExecution.digest_input(values),values,self.parser_version)

    def parse(self, output, **kwargs):
        return super().parse(output,transport='udp',**kwargs)
