"""Integrate explicit network scope, canonical scan entry point and shared environments."""
from pathlib import Path
import ast


def sub(path,old,new,count=1):
    p=Path(path);s=p.read_text()
    if new in s:return
    if s.count(old)!=count:raise RuntimeError((path,old[:90],s.count(old)))
    p.write_text(s.replace(old,new,count))


def func(path,name,change):
    p=Path(path);s=p.read_text();lines=s.splitlines(keepends=True)
    n=next(n for n in ast.parse(s).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name)
    new=change(''.join(lines[n.lineno-1:n.end_lineno]));ast.parse(new)
    lines[n.lineno-1:n.end_lineno]=[new.rstrip()+'\n'];p.write_text(''.join(lines))

sub('scanner/scanner_tools/device_posture.py','    profile = PROFILES[profile_name]', '''    try:
        from .device_scan_scope import with_udp_scope
    except ImportError:
        from device_scan_scope import with_udp_scope
    profile = with_udp_scope(PROFILES[profile_name], options.get('device_udp_ports'))''')
sub('api/devices/router.py','from .shared_collections import save_device_collection, deactivate_device_collection, collection_view',
'''from .shared_collections import save_device_collection, deactivate_device_collection, collection_view
from .collection_environments import bind_environments
from .network_authorization import network_authorization_snapshot''')
sub('api/devices/router.py','    request_collection_ids: list[str] = Field(default_factory=list, max_length=8)',
'''    udp_ports: list[int] | None = Field(default=None, max_length=1024)
    request_collection_environment_ids: dict[str, str | None] = Field(default_factory=dict, max_length=8)
    request_collection_ids: list[str] = Field(default_factory=list, max_length=8)

    @field_validator('udp_ports', mode='before')
    @classmethod
    def validate_udp_scope(cls, value):
        from scanner_tools.device_scan_scope import normalize_udp_ports
        return normalize_udp_ports(value)
''')

def scan(s):
    if 'network_authorization_snapshot' in s:return s
    s=s.replace('        if credential_refs and not safety_contract.credentials_allowed:', '''        request_collection_refs = await bind_environments(conn, request_collection_refs, request.request_collection_environment_ids)
        standing = await network_authorization_snapshot(conn, device_uuid) if not request.confirm_authorized else None
        if not request.confirm_authorized and not standing:
            raise HTTPException(409, 'Standing asset authorization changed during submission; review it before retrying')
        if credential_refs and not safety_contract.credentials_allowed:''',1)
    s=s.replace('            "device_profile": request.profile,','''            "device_profile": request.profile,
            "device_udp_ports": request.udp_ports,
            "asset_authorization_receipt_id": standing['approval_receipt_id'] if standing else None,''',1)
    return s
func('api/devices/router.py','scan_device',scan)

def detail(s):
    if '"authorization": standing' in s:return s
    s=s.replace('    device_payload = _decode_device_row(row)',
        '    async with _pool().acquire() as conn:\n        standing = await network_authorization_snapshot(conn, device_uuid)\n    device_payload = _decode_device_row(row)',1)
    return s.replace('        "device": device_payload,','        "device": device_payload,\n        "authorization": standing,',1)
func('api/devices/router.py','get_device',detail)
sub('api/worker.py','''                if device_target_id and (options or {}).get("run_kind") == "device_posture":
                    options = await _hydrate_device_scan_credentials(options, scan_id)''','''                if device_target_id and (options or {}).get("run_kind") == "device_posture":
                    from devices.network_authorization import revalidate_network_authorization
                    async with db_pool.acquire() as conn:
                        await revalidate_network_authorization(conn,device_target_id,options)
                    options = await _hydrate_device_scan_credentials(options, scan_id)''')
sub('api/devices/worker_inputs.py','from .shared_credentials import resolve_device_credential',
    'from .shared_credentials import resolve_device_credential\nfrom .collection_environments import hydrate_environment')
sub('api/devices/worker_inputs.py','''        resolved.append({
            "collection_id": collection_id,
            "name": str(row.get("name") or ref.get("name") or "Imported requests"),''','''        async with pool.acquire() as conn:
            payload = await hydrate_environment(conn, ref, payload)
        total_bytes += max(0, len(json.dumps(payload,ensure_ascii=False).encode()) - len(raw.encode()))
        if total_bytes > 7 * 1024 * 1024:
            raise ValueError('Device request collections and environments exceed the worker size limit')
        resolved.append({
            "collection_id": collection_id,
            "name": str(row.get("name") or ref.get("name") or "Imported requests"),''')
sub('ui/src/lib/api.ts','export interface DeviceDetailResponse {\n  device: DeviceTarget',
    'export interface DeviceDetailResponse {\n  authorization?: { approved_by: string; approval_receipt_id: string } | null\n  device: DeviceTarget')
p=Path('ui/src/lib/api.ts');s=p.read_text();a=s.index('export async function scanDevice(');b=s.index('export async function getDeviceRequestCollections',a)
part=s[a:b]
if '  udp_ports?: number[]' not in part:
    part=part.replace('  port_hints?: number[]','  port_hints?: number[]\n  udp_ports?: number[]\n  request_collection_environment_ids?: Record<string, string | null>',1)
part=part.replace('/devices/${encodeURIComponent(deviceId)}/scan','/targets/${encodeURIComponent(deviceId)}/network-scans')
p.write_text(s[:a]+part+s[b:])
p='ui/src/app/devices/[id]/page.tsx'
sub(p,"import { DevicePortCoverage } from '@/components/DevicePortCoverage'", "import { DevicePortCoverage } from '@/components/DevicePortCoverage'\nimport { DeviceCollectionEnvironments } from '@/components/DeviceCollectionEnvironments'")
sub(p,"  const [scan, setScan] = useState(","  const [udpPorts, setUdpPorts] = useState('')\n  const [collectionEnvironments, setCollectionEnvironments] = useState<Record<string, string | null>>({})\n  const [webOriginCap, setWebOriginCap] = useState(8)\n  const [scan, setScan] = useState(")
sub(p,'        max_web_origins: 8,','''        max_web_origins: webOriginCap,
        udp_ports: udpPorts.trim() ? parsePortHints(udpPorts) : undefined,
        request_collection_environment_ids: Object.fromEntries(scan.request_collection_ids.map((id) => [id, collectionEnvironments[id] || null])),''')
sub(p,'!workerReady || !scan.confirm_authorized ||','!workerReady || (!scan.confirm_authorized && !data?.authorization) ||')
path=Path(p);s=path.read_text()
if 'Standing asset authorization by' not in s:
    needle='          <label className="flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-100"><input type="checkbox" checked={scan.confirm_authorized}'
    a=s.index(needle);b=s.index('</label>',a)+len('</label>');old=s[a:b]
    s=s[:a]+'          {data?.authorization ? <p className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3 text-sm text-emerald-200">Standing asset authorization by {data.authorization.approved_by} will be rechecked when the scan starts.</p> : ('+old.strip()+')}'+s[b:]
    a=s.index('          <Field label="Safety level"')
    s=s[:a]+'''          <Field label="Custom UDP ports (optional)" hint="Blank uses the profile’s curated ports. Explicit ports replace the UDP scope and are recorded in the receipts."><Input value={udpPorts} onChange={(event) => setUdpPorts(event.target.value)} placeholder="161, 1900, 5353, 5683" /></Field>
          {scan.include_web_dast && <Field label="Maximum web origins" hint="Every interface retains its exact scheme, host, and port."><Input type="number" min={1} max={32} value={webOriginCap} onChange={(event) => setWebOriginCap(Math.min(32,Math.max(1,Number(event.target.value) || 1)))} /></Field>}
'''+s[a:]
    a=s.index('          {data?.authorization ?')
    s=s[:a]+'''          {scan.include_web_dast && scan.request_collection_ids.length > 0 && <DeviceCollectionEnvironments ids={scan.request_collection_ids} selected={collectionEnvironments} onChange={setCollectionEnvironments} />}
'''+s[a:]
    path.write_text(s)
sub('ui/src/components/targets/TargetAssetDetail.tsx','`/hunt?target=${data.target.id}`','`/devices/${data.target.id}/agent`')
p=Path('api/targets/asset_router.py');s=p.read_text()
if 'start_target_network_scan' not in s:
    s+='''\n\ntry:
    from devices.router import DeviceScanRequest
except ModuleNotFoundError:
    from ..devices.router import DeviceScanRequest


@router.post('/targets/{target_id}/network-scans')
async def start_target_network_scan(target_id: str, request: DeviceScanRequest):
    """Canonical entry point; same executor, queue, and ledger as the device view."""
    try:
        from devices.router import scan_device
    except ModuleNotFoundError:
        from ..devices.router import scan_device
    async with pool().acquire() as conn, conn.transaction():
        owner = await ensure_device_profile(conn,target_id,DeviceProfileCreate())
    return await scan_device(str(owner),request)
'''
    p.write_text(s)
