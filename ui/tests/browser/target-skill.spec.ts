import { expect, test, type Page } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

const id = '00000000-0000-4000-8000-000000000311'
const runId = '00000000-0000-4000-8000-000000000312'
const target = {id,asset_id:id,name:'Living room TV',url:'host://tv.test',locator:'tv.test',environment:'lab',is_active:true,connected_device:true,origin_count:0,service_count:0,active_findings_count:0}
const text = '## How to log in\nUse the saved TV administrator profile.\n\n## What to test\nInspect port 8443.\n\n## What to skip\nDo not reboot.'
const skillDocument = (methodology = text, version = '1') => ({schema_version:'hunt-skill/v2',skill_id:`skill.target.${id}`,target_id:id,title:'TV investigation guide',methodology,version,body_sha256:'a'.repeat(64),updated_at:'2026-10-01T12:00:00Z',written_by:'operator:target-skill-api'})

/** The Targets list keeps instructions in each row's menu; the asset page keeps a button. */
async function openInstructions(page: Page, verb: 'Create' | 'Edit') {
  const name = `${verb} instructions for Living room TV`
  if (new URL(page.url()).pathname === '/targets') {
    await page.getByRole('button',{name:'More actions for tv.test'}).click()
    await page.getByRole('menuitem',{name}).click()
  } else await page.getByRole('button',{name}).click()
}

async function mock(page: Page, existing = false, conflict = false, advisory = false) {
  let revision = existing ? 1 : 0
  let saved: ReturnType<typeof skillDocument> | null = existing ? skillDocument() : null
  let operatorSaved = advisory ? skillDocument('Never reboot the device.') : saved
  if (advisory && saved) saved = {...saved, written_by:`hunt:${runId}`}
  const writes: Array<{method:string;body:Record<string,unknown>;revision:string | null}> = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const request = route.request(), url = new URL(request.url())
    if (url.pathname === `/targets/${id}/skill`) {
      if (request.method() !== 'GET') {
        const body = request.postDataJSON() || {}
        writes.push({method:request.method(),body,revision:url.searchParams.get('expected_revision')})
        if (conflict) {
          conflict = false;revision = 2;saved = skillDocument('Instructions saved by another editor.', '2');operatorSaved = saved
          return route.fulfill({status:409,json:{detail:'Target instructions changed. Reload before saving your edits.'}})
        }
        revision += 1
        saved = request.method() === 'DELETE' ? null : {...skillDocument(String(body.methodology),String(revision)),title:String(body.title)}
        operatorSaved = saved; advisory = false
      }
      return route.fulfill({json:{target_id:id,revision,skill:saved,operator_skill:operatorSaved,trust:advisory ? 'hunt_advisory' : saved ? 'operator' : 'none',max_characters:12000}})
    }
    if (url.pathname === '/targets/inventory') return route.fulfill({json:{targets:[target],total:1,offset:0,limit:50}})
    if (url.pathname === `/targets/${id}/asset`) return route.fulfill({json:{target,origins:[],services:[],credentials:[],request_collections:[],active_findings:{},authorization:null}})
    if (url.pathname === `/targets/${id}/history`) return route.fulfill({json:{asset_id:id,kind:'scans',items:[],total:0,offset:0,limit:25}})
    if (url.pathname === `/hunts/${runId}/http-transactions`) return route.fulfill({json:{fidelity:'complete',fidelity_detail:'Synthetic empty archive',total:0,archive_total:0,transactions:[]}})
    if (url.pathname === `/hunts/${runId}`) return route.fulfill({json:{hunt_id:runId,target_id:id,target_kind:'network',target_name:target.name,objective:'Review TV services',status:'completed',budget_profile:'fast',policy:{active_testing:false},budget:{},budget_used:{},actions:[],capabilities:[],skills:[],target_skill:{target_id:id,revision:1,skill:skillDocument(),loaded_at_start:true,editing_affects:'future_hunts',max_characters:12000}}})
    return route.fulfill({json:{status:'healthy',targets:[],workers:[],hunts:[],total:0,rows:[],has_more:false}})
  })
  return writes
}

test('SKILL-001 create, preview, update and delete instructions from the target row', async ({page}) => {
  const writes = await mock(page)
  await page.goto('/targets')
  await openInstructions(page,'Create')
  const dialog = page.getByRole('dialog',{name:'Target instructions',exact:true})
  await dialog.getByRole('button',{name:'Use starter template'}).click()
  await expect(dialog.getByLabel('Instructions',{exact:true})).toHaveValue(/## How to log in/)
  await dialog.getByLabel('Skill title').fill('TV investigation guide')
  await dialog.getByLabel('Instructions',{exact:true}).fill(text)
  await dialog.getByRole('button',{name:'Preview',exact:true}).click()
  await expect(dialog.getByRole('heading',{name:'How to log in'})).toBeVisible()
  await expect(dialog.getByText('Do not reboot.',{exact:true})).toBeVisible()
  await dialog.getByRole('button',{name:'Save instructions',exact:true}).click()
  await expect(dialog).toBeHidden()
  expect(writes[0]).toMatchObject({method:'POST',body:{expected_revision:0,methodology:text}})
  await openInstructions(page,'Edit')
  await expect(dialog.getByLabel('Instructions',{exact:true})).toHaveValue(text)
  await dialog.getByLabel('Instructions',{exact:true}).fill(text+'\nCheck the management API.')
  await dialog.getByRole('button',{name:'Save instructions',exact:true}).click()
  await expect(dialog).toBeHidden()
  expect(writes[1]).toMatchObject({method:'PUT',body:{expected_revision:1}})
  await openInstructions(page,'Edit')
  await dialog.getByRole('button',{name:'Delete',exact:true}).click()
  await expect(dialog.getByText(/Existing Hunts keep their snapshot/)).toBeVisible()
  await dialog.getByRole('button',{name:'Delete instructions',exact:true}).click()
  await expect(dialog).toBeHidden()
  expect(writes[2]).toMatchObject({method:'DELETE',revision:'2'})
  await page.getByRole('button',{name:'More actions for tv.test'}).click()
  await expect(page.getByRole('menuitem',{name:'Create instructions for Living room TV'})).toBeVisible()
})

test('SKILL-002 dirty drafts survive cancellation until explicitly discarded', async ({page}) => {
  const writes = await mock(page,true)
  await page.goto('/targets')
  await openInstructions(page,'Create')
  const dialog = page.getByRole('dialog',{name:'Target instructions',exact:true})
  await dialog.getByLabel('Instructions',{exact:true}).fill('My unsaved draft')
  await dialog.getByRole('button',{name:'Cancel',exact:true}).click()
  await expect(dialog.getByText('Discard your unsaved changes?')).toBeVisible()
  await dialog.getByRole('button',{name:'Keep editing'}).click()
  await expect(dialog.getByLabel('Instructions',{exact:true})).toHaveValue('My unsaved draft')
  await page.keyboard.press('Escape')
  await dialog.getByRole('button',{name:'Discard changes'}).click()
  await expect(dialog).toBeHidden()
  expect(writes).toEqual([])
})

test('SKILL-003 a conflicting save preserves the draft and offers an explicit reload', async ({page}) => {
  const writes = await mock(page,true,true)
  await page.goto('/targets')
  await openInstructions(page,'Create')
  const dialog = page.getByRole('dialog',{name:'Target instructions',exact:true})
  await dialog.getByLabel('Instructions',{exact:true}).fill('Draft from this editor')
  await dialog.getByRole('button',{name:'Save instructions'}).click()
  await expect(dialog.getByRole('alert')).toContainText('Target instructions changed')
  await expect(dialog.getByLabel('Instructions',{exact:true})).toHaveValue('Draft from this editor')
  await dialog.getByRole('button',{name:'Discard draft and reload'}).click()
  await expect(dialog.getByLabel('Instructions',{exact:true})).toHaveValue('Instructions saved by another editor.')
  await expect(dialog.getByText('Saved version 2')).toBeVisible()
  expect(writes).toHaveLength(1)
})

test('SKILL-004 failed reads cannot enable a destructive overwrite', async ({page}) => {
  const writes = await mock(page)
  await page.route(`${MOCK_API_ORIGIN}/targets/${id}/skill`,route => route.fulfill({status:503,json:{detail:'Database unavailable'}}))
  await page.goto('/targets')
  await openInstructions(page,'Create')
  const dialog = page.getByRole('dialog',{name:'Target instructions',exact:true})
  await expect(dialog.getByRole('alert')).toContainText('Database unavailable')
  await expect(dialog.getByRole('button',{name:'Save instructions'})).toBeDisabled()
  expect(writes).toEqual([])
})

test('SKILL-005 target detail editor is usable at desktop and mobile widths', async ({page}, testInfo) => {
  await mock(page,true)
  await page.goto(`/targets/${id}/asset`)
  await expect(page.getByText('TV investigation guide',{exact:true})).toBeVisible()
  await openInstructions(page,'Edit')
  const dialog = page.getByRole('dialog',{name:'Target instructions',exact:true})
  await expect(dialog.getByLabel('Instructions',{exact:true})).toHaveValue(text)
  await expect(dialog.getByRole('button',{name:'Save instructions'})).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)).toBe(false)
  await page.screenshot({path:testInfo.outputPath('target-skill-editor.png')})
})

test('SKILL-006 Hunt review retains its startup snapshot while editing future instructions', async ({page}) => {
  const writes = await mock(page,true)
  await page.goto(`/hunt?target=${id}&run=${runId}`)
  await expect(page.getByRole('heading',{name:'Target instructions at startup'})).toBeVisible()
  await page.getByText('TV investigation guide',{exact:true}).click()
  await expect(page.getByText('Inspect port 8443.',{exact:true})).toBeVisible()
  await openInstructions(page,'Edit')
  const dialog = page.getByRole('dialog',{name:'Target instructions',exact:true})
  await dialog.getByLabel('Instructions',{exact:true}).fill('Changed for future Hunts')
  await dialog.getByRole('button',{name:'Save instructions'}).click()
  await expect(dialog).toBeHidden()
  await expect(page.getByText('Inspect port 8443.',{exact:true})).toBeVisible()
  expect(writes).toHaveLength(1)
  expect(writes[0].method).toBe('PUT')
})


test('SKILL-007 unchanged Hunt draft requires an explicit operator save, while baseline stays visible', async ({page}) => {
  const writes = await mock(page,true,false,true)
  await page.goto(`/targets/${id}/asset`)
  await openInstructions(page,'Edit')
  const dialog = page.getByRole('dialog',{name:'Target instructions',exact:true})
  await expect(dialog.getByTestId('target-instruction-trust')).toContainText('advisory draft')
  await dialog.getByText('Current operator instructions (still used by new Hunts)').click()
  await expect(dialog.getByText('Never reboot the device.',{exact:true})).toBeVisible()
  const save = dialog.getByRole('button',{name:'Save as operator instructions',exact:true})
  await expect(save).toBeEnabled()
  await save.click()
  await expect(dialog).toBeHidden()
  expect(writes).toHaveLength(1)
  expect(writes[0]).toMatchObject({method:'PUT',body:{expected_revision:1,methodology:text}})
  await openInstructions(page,'Edit')
  await expect(dialog.getByTestId('target-instruction-trust')).toHaveCount(0)
  await expect(dialog.getByRole('button',{name:'Save instructions',exact:true})).toBeDisabled()
})
