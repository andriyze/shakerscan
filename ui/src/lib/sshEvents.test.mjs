import test from 'node:test'
import assert from 'node:assert/strict'
import {createSseDecoder} from './sshEvents.mjs'

test('SSH events survive split chunks and CRLF; cumulative output stays separate',()=>{
  const events=[];const decoder=createSseDecoder((name,value)=>events.push([name,value]))
  const text=': heartbeat\r\nevent: output\r\ndata: {"stdout":"first"}\r\n\r\nevent: output\ndata: {"stdout":"firstsecond"}\n\nevent: result\ndata: {"ok":true}\n\n'
  for (const char of text) decoder.push(char)
  decoder.finish()
  assert.deepEqual(events,[['output',{stdout:'first'}],['output',{stdout:'firstsecond'}],['result',{ok:true}]])
})
test('Malformed, oversized, or truncated SSH events are errors',()=>{
  assert.throws(()=>createSseDecoder(()=>{}).push('data: nope\n\n'))
  const partial=createSseDecoder(()=>{});partial.push('event: result\ndata: {"')
  assert.throws(()=>partial.finish())
  assert.throws(()=>createSseDecoder(()=>{}).push('x'.repeat(2097153)))
})
