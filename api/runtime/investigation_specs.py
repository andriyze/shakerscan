"""Typed additions to the existing canonical browser and network runtime."""
def investigation_specs(spec,schema,kinds):
    browser = spec('browser.workflow',
        'Run an authorized sequence of non-secret fills and clicks, including forms and test-object cleanup, on one pinned HTTP service.',
        'browser','active',kinds,'playwright','1','state_changing_http',
        {'browser_actions':9,'http_requests':50,'state_changing_requests':4,'tool_wall_seconds':30},
        {'network_reachability':True,'browser_runtime':'playwright','agent_tool_worker':True,
         'runtime_target_binding':True,'state_changing_http':True},
        schema({'origin':{'type':'string','maxLength':2048},'path':{'type':'string','maxLength':2000},
                'session_ref':{'type':'string','format':'uuid'},
                'steps':{'type':'array','minItems':1,'maxItems':8,'items':schema({
                    'action':{'type':'string','enum':['click','fill']},
                    'selector':{'type':'string','minLength':1,'maxLength':500},
                    'value':{'type':'string','maxLength':500}},required=('action','selector'))},
                'timeout_ms':{'type':'integer','minimum':1000,'maximum':30000},
                'max_requests':{'type':'integer','minimum':1,'maximum':50},
                'max_state_changing_requests':{'type':'integer','minimum':1,'maximum':20},
                'settle_ms':{'type':'integer','minimum':0,'maximum':2000},
                'wait_until':{'type':'string','enum':['domcontentloaded','load']}},
                required=('steps',)),
        'browser-interaction/v1',('browser_interaction_observation','http_observation','tool_receipt'),
        default_timeout_ms=30000,hunt_executor='worker_browser')
    snmp = spec('service.snmp.inspect',
        'Inspect SNMPv3 engine information without community strings, credential guesses, OID walks or SET operations.',
        'network_udp','active',kinds,'nmap','1','network_discovery',
        {'hosts_attempted':1,'udp_ports_attempted':1,'tool_wall_seconds':30},
        {'network_reachability':True,'binary':'nmap','server_owned_nse_allowlist':True},
        schema({'port':{'type':'integer','minimum':1,'maximum':65535}}),
        'nmap-nse-observation/v1',('nse_observation','tool_receipt'),
        binary='nmap',default_timeout_ms=30000,version_args=('--version',),common_paths=('/opt/tools/nmap',),
        hunt_executor='worker_network')
    return browser,snmp
