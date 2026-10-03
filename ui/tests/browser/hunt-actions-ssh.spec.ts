import {expect,test} from '@playwright/test'
import {MOCK_API_ORIGIN,pinMockApiOrigin} from './mock-api-origin'
const id='00000000-0000-4000-8000-000000000351'
const run='00000000-0000-4000-8000-000000000352'
const actionId='00000000-0000-4000-8000-000000000353'
test.use({launchOptions:{args:['--host-resolver-rules=MAP shakerscan-qa.invalid 127.0.0.1']}})
test('saved target actions create, edit and delete without executing network traffic',async({page})=>{
  await pinMockApiOrigin(page)
  let revision=0,actions:Record<string,unknown>[]=[],executions=0
  await page.route(`${MOCK_API_ORIGIN}/**`,async route=>{
    const request=route.request(),path=new URL(request.url()).pathname
    if(path.startsWith(`/targets/${id}/actions`)) {
      if(request.method()==='POST'||request.method()==='PUT') {
        const value=request.postDataJSON();expect(value.expected_revision).toBe(revision)
        actions=[{...value,id:actionId,target_id:id,revision:++revision}]
      } else if(request.method()==='DELETE'){actions=[];revision++}
      return route.fulfill({json:{target_id:id,revision,actions,max_actions:32,authority_granted:false}})
    }
    if(path===`/targets/${id}/asset`)return route.fulfill({json:{target:{id,name:'TV action fixture',locator:'tv.test',url:'host://tv.test',is_active:true,environment:'lab'},origins:[],services:[],credentials:[],request_collections:[],active_findings:{}}})
    if(path==='/hunts/contract')return route.fulfill({json:{tool_calls:[{name:'ssh.exec'},{name:'ports.discover'}]}})
    if(path.endsWith('/history'))return route.fulfill({json:{items:[],total:0,offset:0,limit:25}})
    if(path.includes('/capabilities/'))executions++
    return route.fulfill({status:404,json:{detail:'No fixture'}})
  })
  await page.goto(`/targets/${id}/asset`)
  await page.getByRole('button',{name:'Add action',exact:true}).click()
  const dialog=page.getByRole('dialog',{name:'Create saved action'})
  await dialog.getByLabel('Action name').fill('Check TV logs')
  await dialog.getByLabel('Remote command').fill('tail -n 40 /var/log/messages')
  await dialog.getByLabel('SSH port').fill('2222')
  await dialog.getByRole('button',{name:'Save action',exact:true}).click()
  await expect(page.getByRole('heading',{name:'Check TV logs'})).toBeVisible()
  expect(actions[0].steps).toEqual([{capability:'ssh.exec',input:{command:'tail -n 40 /var/log/messages',port:2222}}])
  await page.getByRole('button',{name:'Edit Check TV logs'}).click()
  await page.getByRole('dialog').getByLabel('Action name').fill('Check service logs')
  await page.getByRole('dialog').getByRole('button',{name:'Save action',exact:true}).click()
  await expect(page.getByRole('heading',{name:'Check service logs'})).toBeVisible()
  await expect(page.getByRole('link',{name:'Start Hunt',exact:true}).last()).toHaveAttribute('href',/targets.actions.read/)
  await page.getByRole('button',{name:'Delete Check service logs'}).click()
  await expect(page.getByRole('heading',{name:'Check service logs'})).toHaveCount(0)
  expect(revision).toBe(3);expect(executions).toBe(0)
})

test.describe('HTTP LAN SSH',()=>{
test('live SSH displays stdout and stderr and saves a reusable action',async({page})=>{
  await pinMockApiOrigin(page)
  let submitted:Record<string,unknown>={},saved:Record<string,unknown>={},closed:Record<string,unknown>={}
  const hunt={hunt_id:run,target_id:id,target_kind:'network',objective:'Check logs',status:'active',
    budget_profile:'fast',policy:{active_testing:true},budget:{},budget_used:{},actions:[],
    capabilities:[{name:'ssh.exec',description:'Direct SSH',risk_tier:'active'},{name:'ssh.close',risk_tier:'read_only'}]}
  await page.route(`${MOCK_API_ORIGIN}/**`,async route=>{
    const request=route.request(),path=new URL(request.url()).pathname
    if(path===`/hunts/${run}`)return route.fulfill({json:hunt})
    if(path===`/hunts/${run}/capabilities/ssh.close`){
      closed=request.postDataJSON()
      return route.fulfill({json:{action_result:{status:'success'},result:{status:'success'}}})
    }
    if(path===`/hunts/${run}/ssh/exec`){
      submitted=request.postDataJSON()
      const output={kind:'ssh_command_observation',stdout:'fixture-log\n',stderr:'fixture-warning\n',exit_status:0,session_id:actionId}
      return route.fulfill({contentType:'text/event-stream',body:
        `event: accepted\ndata: ${JSON.stringify({action_id:actionId})}\n\nevent: output\ndata: ${JSON.stringify(output)}\n\nevent: result\ndata: ${JSON.stringify({result:{typed_output:{records:[output]}}})}\n\n`})
    }
    if(path===`/targets/${id}/actions`){
      if(request.method()==='POST')saved=request.postDataJSON()
      return route.fulfill({json:{target_id:id,revision:0,actions:[],max_actions:32,authority_granted:false}})
    }
    if(path.endsWith('/http-transactions'))return route.fulfill({json:{transactions:[],total:0,archive_total:0,fidelity:'complete'}})
    return route.fulfill({status:404,json:{detail:'No fixture'}})
  })
  const url=new URL(`/hunt?run=${run}#ssh`,test.info().project.use.baseURL || 'http://127.0.0.1:3000')
  url.hostname='shakerscan-qa.invalid'
  await page.goto(url.toString())
  expect(await page.evaluate(()=>window.isSecureContext)).toBe(false)
  expect(await page.evaluate(()=>typeof crypto.randomUUID)).toBe('undefined')
  await expect(page.getByRole('heading',{name:'Live SSH',exact:true})).toBeVisible()
  await page.getByLabel('Remote command').fill('tail -n 40 /var/log/messages')
  await page.getByLabel('Port',{exact:true}).fill('2222')
  await page.getByRole('button',{name:'Run command',exact:true}).click()
  await expect(page.getByLabel('SSH stdout')).toContainText('fixture-log')
  await expect(page.getByLabel('SSH stderr')).toContainText('fixture-warning')
  await page.getByRole('button',{name:'Save action',exact:true}).click()
  await expect(page.getByText('Command saved as a reusable target action.')).toBeVisible()
  expect(submitted.input).toMatchObject({command:'tail -n 40 /var/log/messages',port:2222})
  expect(submitted.idempotency_key).toMatch(/^ui-ssh-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  expect(saved.steps).toEqual([{capability:'ssh.exec',input:{command:'tail -n 40 /var/log/messages',port:2222}}])
  await expect(page.getByLabel('Port',{exact:true})).toBeDisabled()
  await page.getByRole('button',{name:'Disconnect SSH',exact:true}).click()
  await expect(page.getByText('SSH disconnected. You can choose another port.')).toBeVisible()
  expect(closed.input).toEqual({session_id:actionId})
  await expect(page.getByLabel('Port',{exact:true})).toBeEnabled()
  await page.getByLabel('Port',{exact:true}).fill('22')
  await expect(page.getByText('Connect on first command')).toBeVisible()
})
})

for (const outcome of [
  {status:'failed',error:'SSH host trust changed',stdout:''},
  {status:'failed',error:'Credential grant was revoked',stdout:''},
  {status:'failed',error:'ssh_session_worker_unavailable',stdout:''},
  {status:'cancelled',error:'cancelled',stdout:'last log line before interruption\n'},
  {status:'partial',error:'ssh_action_deadline',stdout:'partial log output\n'},
]) test(`live SSH exposes ${outcome.error} with its terminal status`,async({page})=>{
  await pinMockApiOrigin(page)
  const output={kind:'ssh_command_observation',stdout:outcome.stdout,stderr:'',
    connection_closed:true,status:outcome.status,execution_uncertain:outcome.status==='cancelled'}
  await page.route(`${MOCK_API_ORIGIN}/**`,async route=>{
    const path=new URL(route.request().url()).pathname
    if(path===`/hunts/${run}`)return route.fulfill({json:{hunt_id:run,target_id:id,target_kind:'network',
      objective:'Check logs',status:'active',budget_profile:'fast',policy:{active_testing:true},
      budget:{},budget_used:{},actions:[],capabilities:[{name:'ssh.exec',risk_tier:'active'}]}})
    if(path===`/hunts/${run}/ssh/exec`)return route.fulfill({contentType:'text/event-stream',body:
      `event: accepted\ndata: ${JSON.stringify({action_id:actionId})}\n\nevent: result\ndata: ${JSON.stringify({action_result:{status:outcome.status,errors:[outcome.error]},result:{status:outcome.status,error:outcome.error,typed_output:{records:[output]}}})}\n\n`})
    if(path.endsWith('/http-transactions'))return route.fulfill({json:{transactions:[],total:0,archive_total:0,fidelity:'complete'}})
    return route.fulfill({status:404,json:{detail:'No fixture'}})
  })
  await page.goto(`/hunt?run=${run}#ssh`)
  await page.getByLabel('Remote command').fill('tail -n 20 /var/log/messages')
  await page.getByRole('button',{name:'Run command',exact:true}).click()
  await expect(page.getByRole('alert').filter({hasText:outcome.error})).toBeVisible()
  await expect(page.getByLabel('SSH command outcome')).toContainText(outcome.status)
  if(outcome.stdout)await expect(page.getByLabel('SSH stdout')).toContainText(outcome.stdout.trim())
  await expect(page.getByText('Connect on first command')).toBeVisible()
})

test('completed Hunt explains why SSH commands cannot be submitted',async({page})=>{
  await pinMockApiOrigin(page)
  let executions=0
  await page.route(`${MOCK_API_ORIGIN}/**`,async route=>{
    const path=new URL(route.request().url()).pathname
    if(path===`/hunts/${run}`)return route.fulfill({json:{hunt_id:run,target_id:id,
      target_kind:'network',objective:'Finished log investigation',status:'completed',
      budget_profile:'fast',policy:{active_testing:true},budget:{},budget_used:{},actions:[],
      capabilities:[{name:'ssh.exec',description:'Direct SSH',risk_tier:'active'}]}})
    if(path.endsWith('/ssh/exec'))executions++
    if(path.endsWith('/http-transactions'))return route.fulfill({json:{transactions:[],total:0,archive_total:0,fidelity:'complete'}})
    return route.fulfill({status:404,json:{detail:'No fixture'}})
  })
  await page.goto(`/hunt?run=${run}#ssh`)
  await expect(page.getByText('This Hunt has ended. Start a new Hunt to run SSH commands.')).toBeVisible()
  await page.getByLabel('Remote command').fill('uname -s')
  await expect(page.getByRole('button',{name:'Run command',exact:true})).toBeDisabled()
  expect(executions).toBe(0)
})
