/** Incremental SSE decoder. Output snapshots replace previous output, never append it. */
export function createSseDecoder(onEvent) {
  let buffer = ''
  let event = ''
  let data = []
  function line(value) {
    if (!value) {
      if (data.length) onEvent(event || 'message', JSON.parse(data.join('\n')))
      event = ''; data = []
    } else if (value.startsWith('event:')) event = value.slice(6).trim()
    else if (value.startsWith('data:')) data.push(value.slice(5).trimStart())
  }
  return {
    push(value) {
      buffer += value
      if (buffer.length > 2097152) throw new Error('SSH event exceeded the output limit')
      let index
      while ((index = buffer.indexOf('\n')) >= 0) {
        line(buffer.slice(0,index).replace(/\r$/,''));buffer = buffer.slice(index+1)
      }
    },
    finish() {if (buffer.trim()) throw new Error('Incomplete SSH event stream')},
  }
}
