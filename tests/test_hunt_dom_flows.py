"""DOM-XSS leads in a script (ported from the removed scanner_tools/dom_xss_analyzer)."""
from __future__ import annotations

import asyncio
import json

from api.capabilities.dom_flows import dom_xss_leads
from api.hunt.server_sweep import Sweep

BUNDLE = ('var a=1;function r(){var q=new URLSearchParams(location.search).get("q");'
          'document.getElementById("o").innerHTML="<b>"+q+"</b>"}'
          'window.addEventListener("hashchange",function(){$("#t").html(decodeURIComponent(location.hash.slice(1)))});')


def test_a_minified_source_shortly_before_a_sink_is_a_lead_with_its_parameter():
    leads = dom_xss_leads(BUNDLE)
    assert {"source": "location.search", "sink": "innerHTML", "parameter": "q"} in leads
    assert {"source": "location.hash", "sink": "jquery_html"} in leads


def test_a_sink_far_from_any_source_or_a_bundle_without_sources_is_no_lead():
    assert dom_xss_leads('var x=location.hash;' + ";" * 400 + 'el.innerHTML=y') == []
    assert dom_xss_leads('el.innerHTML="<b>static</b>";document.write("x")') == []


def test_the_sweep_sends_the_browser_proof_for_each_parameter_a_script_reads_into_a_sink():
    calls = []

    async def call(capability, values, key):
        calls.append((capability, dict(values)))
        if capability == "javascript.analyze":
            return {"action_id": "js", "action_result": {"status": "success", "observations": [
                {"kind": "javascript_analysis", "routes": [], "dom_xss_leads": dom_xss_leads(BUNDLE)}]}}
        return {"action_id": "x", "action_result": {"status": "success", "observations": []}}

    async def create(values):
        return {"candidate": {"id": "c"}}

    async def live():
        return True

    sweep = Sweep(call=call, create_candidate=create, state={}, live=live)
    sweep.xss_tool = True

    async def scenario():
        await sweep._javascript([{"endpoint": "GET /static/app.js"}])
        await sweep._drain() if hasattr(sweep, "_drain") else None
        for _ in range(20):
            await asyncio.sleep(0)

    asyncio.run(scenario())
    proofs = [values for capability, values in calls if capability == "xss.verify"]
    assert {"path": "/?q=1", "deep_domxss": True} in proofs
    assert json.dumps(proofs).count("deep_domxss") == len(proofs) == 1  # the hash lead names no parameter
