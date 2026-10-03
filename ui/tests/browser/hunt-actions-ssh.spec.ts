import {expect,test} from '@playwright/test'
import {MOCK_API_ORIGIN,pinMockApiOrigin} from './mock-api-origin'
const id='00000000-0000-4000-8000-000000000351'
const run='00000000-0000-4000-8000-000000000352'
const actionId='00000000-0000-4000-8000-000000000353'
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

test('live SSH displays stdout and stderr and saves a reusable action',async({page})=>{
  await pinMockApiOrigin(page)
  let submitted:Record<string,unknown>={},saved:Record<string,unknown>={}
  const hunt={hunt_id:run,target_id:id,target_kind:'network',objective:'Check logs',status:'active',
    budget_profile:'fast',policy:{active_testing:true},budget:{},budget_used:{},actions:[],
    capabilities:[{name:'ssh.exec',description:'Direct SSH',risk_tier:'active'}]}
  await page.route(`${MOCK_API_ORIGIN}/**`,async route=>{
    const request=route.request(),path=new URL(request.url()).pathname
    if(path===`/hunts/${run}`)return route.fulfill({json:hunt})
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
  await page.goto(`/hunt?run=${run}#ssh`)
  await expect(page.getByRole('heading',{name:'Live SSH',exact:true})).toBeVisible()
  await page.getByLabel('Remote command').fill('tail -n 40 /var/log/messages')
  await page.getByLabel('Port',{exact:true}).fill('2222')
  await page.getByRole('button',{name:'Run command',exact:true}).click()
  await expect(page.getByLabel('SSH stdout')).toContainText('fixture-log')
  await expect(page.getByLabel('SSH stderr')).toContainText('fixture-warning')
  await page.getByRole('button',{name:'Save action',exact:true}).click()
  await expect(page.getByText('Command saved as a reusable target action.')).toBeVisible()
  expect(submitted.input).toMatchObject({command:'tail -n 40 /var/log/messages',port:2222})
  expect(saved.steps).toEqual([{capability:'ssh.exec',input:{command:'tail -n 40 /var/log/messages',port:2222}}])
})
