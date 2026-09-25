// A deliberately small DNS wire codec: parses only facts used by this service and skips
// other RDATA without executing a general-purpose decoder. All offsets/loops are bounded.
export const TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, DS: 43, OPT: 41, DNSKEY: 48, HTTPS: 65, CAA: 257 } as const;
export type QueryType = 'A' | 'AAAA' | 'NS' | 'SOA' | 'PTR' | 'CAA' | 'MX' | 'TXT' | 'DS' | 'DNSKEY' | 'HTTPS';
export interface RecordData {
  name: string;
  type: number;
  value?: string;
  preference?: number;
  tag?: string;
  flags?: number;
  ttl?: number;
  serial?: number;
  algorithm?: number;
  keyTag?: number;
  params?: string[];
  section: 'answer' | 'authority' | 'additional';
}
export interface DnsAnswer {
  state: 'ok'; rcode: number; ad: boolean; aa: boolean; records: RecordData[];
}
function invalid(): never { throw new Error('invalid_dns'); }
export function encodeQuery(host: string, type: QueryType, id: number): Uint8Array {
  const labels = host === '.' ? [] : host.split('.');
  if (labels.some(l => !l.length || l.length > 63) || host.length > 253) invalid();
  const data = new Uint8Array(12 + labels.reduce((n, label) => n + label.length + 1, 1) + 4 + 11);
  const view = new DataView(data.buffer);
  view.setUint16(0, id); view.setUint16(2, 0x0100); // RD; never CD.
  view.setUint16(4, 1); view.setUint16(10, 1);
  let pos = 12;
  for (const label of labels) {
    data[pos++] = label.length;
    for (const ch of label) data[pos++] = ch.charCodeAt(0);
  }
  data[pos++] = 0;
  view.setUint16(pos, TYPES[type]); pos += 2;
  view.setUint16(pos, 1); pos += 2;
  data[pos++] = 0; view.setUint16(pos, TYPES.OPT); pos += 2;
  view.setUint16(pos, 1232); pos += 2;
  view.setUint32(pos, 0x8000); pos += 4; // EDNS DO bit; resolver validates DNSSEC.
  view.setUint16(pos, 0);
  return data;
}
export function decodeAnswer(data: Uint8Array, expected: { host: string; type: QueryType; id: number }): DnsAnswer {
  if (data.length < 12 || data.length > 32768) invalid();
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const need = (offset: number, bytes: number, end = data.length) => { if (offset < 0 || offset + bytes > end) invalid(); };
  const u16 = (offset: number) => { need(offset, 2); return view.getUint16(offset); };
  const flags = u16(2);
  if (u16(0) !== expected.id || !(flags & 0x8000) || (flags & 0x7a10) || u16(4) !== 1) invalid();
  const counts = [u16(6), u16(8), u16(10)];
  if (counts.reduce((a, b) => a + b, 0) > 128) invalid();
  const name = (start: number, end = data.length): { value: string; next: number } => {
    let pos = start, next = -1, expanded = 1, jumps = 0, labels = 0;
    let limit = end;
    const parts: string[] = [];
    while (true) {
      need(pos, 1, limit);
      const size = data[pos++]!;
      if ((size & 0xc0) === 0xc0) {
        need(pos, 1, limit);
        const pointer = ((size & 0x3f) << 8) | data[pos++]!;
        if (pointer < 12 || pointer >= pos - 2 || ++jumps > 32) invalid();
        if (next < 0) next = pos;
        pos = pointer; limit = data.length;
        continue;
      }
      if (size & 0xc0) invalid();
      if (size === 0) return { value: parts.join('.').toLowerCase(), next: next < 0 ? pos : next };
      need(pos, size, limit);
      expanded += size + 1;
      if (expanded > 255 || ++labels > 127) invalid();
      let part = '';
      for (const ch of data.subarray(pos, pos + size)) {
        if (ch < 33 || ch > 126 || ch === 46 || ch === 92) invalid();
        part += String.fromCharCode(ch);
      }
      parts.push(part); pos += size;
    }
  };
  const q = name(12);
  let pos = q.next;
  if (q.value !== (expected.host === '.' ? '' : expected.host) || u16(pos) !== TYPES[expected.type] || u16(pos + 2) !== 1) invalid();
  pos += 4;
  const records: RecordData[] = [];
  const sections = ['answer', 'authority', 'additional'] as const;
  for (let section = 0; section < 3; section++) {
    for (let i = 0; i < counts[section]!; i++) {
      const owner = name(pos); pos = owner.next; need(pos, 10);
      const type = u16(pos), klass = u16(pos + 2), ttl = view.getUint32(pos + 4), size = u16(pos + 8);
      pos += 10;
      const end = pos + size; need(pos, size);
      if (type === TYPES.OPT) {
        // Reject extended errors, unsupported EDNS versions and malformed option framing.
        if (owner.value || section !== 2 || (ttl >>> 16) !== 0) invalid();
        let opt = pos;
        while (opt < end) { need(opt, 4, end); const len = u16(opt + 2); opt += 4; need(opt, len, end); opt += len; }
      } else {
        if (klass !== 1) invalid();
        const record: RecordData = { name: owner.value, type, section: sections[section]!, ttl };
        if (type === TYPES.A) {
          if (size !== 4) invalid();
          record.value = [...data.subarray(pos, end)].join('.');
        } else if (type === TYPES.AAAA) {
          if (size !== 16) invalid();
          record.value = Array.from({ length: 8 }, (_, i) => u16(pos + i * 2).toString(16)).join(':');
        } else if ([TYPES.CNAME, TYPES.NS, TYPES.PTR, TYPES.MX].includes(type as 2)) {
          let start = pos;
          if (type === TYPES.MX) { need(pos, 2, end); record.preference = u16(pos); start += 2; }
          const target = name(start, end);
          if (target.next !== end) invalid();
          record.value = target.value;
        } else if (type === TYPES.TXT) {
          const pieces: number[] = [];
          let cursor = pos;
          while (cursor < end) {
            const length = data[cursor++]!; need(cursor, length, end);
            for (const ch of data.subarray(cursor, cursor + length)) pieces.push(ch);
            cursor += length;
          }
          if (pieces.length > 4096) invalid();
          record.value = String.fromCharCode(...pieces);
        } else if (type === TYPES.CAA) {
          need(pos, 2, end); const length = data[pos + 1]!; need(pos + 2, length, end);
          record.flags = data[pos]!;
          record.tag = String.fromCharCode(...data.subarray(pos + 2, pos + 2 + length)).toLowerCase();
          const value = data.subarray(pos + 2 + length, end);
          if (value.length <= 512 && value.every(ch => ch >= 32 && ch <= 126)) record.value = String.fromCharCode(...value);
        } else if (type === TYPES.SOA) {
          const mname = name(pos, end), rname = name(mname.next, end);
          if (rname.next + 20 !== end) invalid();
          record.serial = view.getUint32(rname.next);
        } else if (type === TYPES.DS) {
          if (size < 4) invalid();
          record.keyTag = u16(pos); record.algorithm = data[pos + 2]!;
        } else if (type === TYPES.DNSKEY) {
          if (size < 4) invalid();
          record.algorithm = data[pos + 3]!;
        } else if (type === TYPES.HTTPS) {
          need(pos, 2, end);
          record.preference = u16(pos);
          const target = name(pos + 2, end);
          record.value = target.value || '.';
          let cursor = target.next, lastKey = -1;
          const params: string[] = [];
          while (cursor < end) {
            need(cursor, 4, end);
            const key = u16(cursor), length = u16(cursor + 2);
            cursor += 4; need(cursor, length, end);
            if (key <= lastKey) invalid();
            lastKey = key;
            if (key === 1) {
              let at = cursor;
              const alpns: string[] = [];
              while (at < cursor + length) {
                const n = data[at++]!;
                if (!n || at + n > cursor + length) invalid();
                const value = String.fromCharCode(...data.subarray(at, at + n));
                if (/^[a-zA-Z0-9_.-]{1,32}$/.test(value)) alpns.push(value);
                at += n;
              }
              params.push(`alpn=${alpns.join(',')}`);
            } else if (key === 3 && length === 2) params.push(`port=${u16(cursor)}`);
            else if (key === 5) params.push('ech=present');
            else params.push(`key${key}=present`);
            cursor += length;
          }
          record.params = params.slice(0, 16);
        }
        records.push(record);
      }
      pos = end;
    }
  }
  if (pos !== data.length) invalid();
  return { state: 'ok', rcode: flags & 15, ad: Boolean(flags & 0x20), aa: Boolean(flags & 0x0400), records };
}
