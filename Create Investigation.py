"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'start_investigations_1' block
    start_investigations_1(container=container)

    return

@phantom.playbook_block()
def start_investigations_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("start_investigations_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:name","finding:owner","finding:status","finding:urgency","finding:description","finding:disposition","finding:id","finding:consolidated_findings.event_id","finding:sensitivity","finding:consolidated_findings.investigation_type"])

    parameters = []

    # build parameters list for 'start_investigations_1' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None:
            parameters.append({
                "name": finding_data_item[0],
                "owner": finding_data_item[1],
                "status": finding_data_item[2],
                "urgency": finding_data_item[3],
                "description": finding_data_item[4],
                "disposition": finding_data_item[5],
                "finding_ids": [
                    finding_data_item[6],
                    finding_data_item[7],
                ],
                "sensitivity": finding_data_item[8],
                "investigation_type": finding_data_item[9],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("start investigations", parameters=parameters, name="start_investigations_1", assets=["builtin_mc_connector"], callback=get_finding_or_investigation_2)

    return


@phantom.playbook_block()
def get_finding_or_investigation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_finding_or_investigation_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    start_investigations_1_result_data = phantom.collect2(container=container, datapath=["start_investigations_1:action_result.data.*.id","start_investigations_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_finding_or_investigation_2' call
    for start_investigations_1_result_item in start_investigations_1_result_data:
        if start_investigations_1_result_item[0] is not None:
            parameters.append({
                "id": start_investigations_1_result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get finding or investigation", parameters=parameters, name="get_finding_or_investigation_2", assets=["builtin_mc_connector"], callback=get_playbook_name)

    return


@phantom.playbook_block()
def get_playbook_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_playbook_name() called")

    get_finding_or_investigation_2_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_2:action_result.data.*.response_plans.*.phases.*.tasks.*.suggestions.playbooks.*.playbook_id"], action_results=results)

    get_finding_or_investigation_2_result_item_0 = [item[0] for item in get_finding_or_investigation_2_result_data]

    get_playbook_name__playbook_name = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    playbook_name = []
    for item in get_finding_or_investigation_2_result_item_0:
        playbook_name.append(item)

    get_playbook_name__playbook_name = playbook_name
    
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="get_playbook_name__inputs:0:get_finding_or_investigation_2:action_result.data.*.response_plans.*.phases.*.tasks.*.suggestions.playbooks.*.playbook_id", value=json.dumps(get_finding_or_investigation_2_result_item_0))

    phantom.save_block_result(key="get_playbook_name:playbook_name", value=json.dumps(get_playbook_name__playbook_name))

    playbook_dispatch_playbooks_2(container=container)

    return


@phantom.playbook_block()
def playbook_dispatch_playbooks_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_dispatch_playbooks_1() called")

    get_playbook_name__playbook_name = json.loads(_ if (_ := phantom.get_run_data(key="get_playbook_name:playbook_name")) != "" else "null")  # pylint: disable=used-before-assignment

    inputs = {
        "playbook_name": get_playbook_name__playbook_name,
        "playbook_tags": ["phishing"],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "boq_dev/dispatch_playbooks", returns the playbook_run_id
    playbook_run_id = phantom.playbook("boq_dev/dispatch_playbooks", container=container, name="playbook_dispatch_playbooks_1", callback=playbook_dispatch_playbooks_1_callback, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_dispatch_playbooks_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_dispatch_playbooks_1_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


    return


@phantom.playbook_block()
def another_dispatch_playbooks_with_dlp_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("another_dispatch_playbooks_with_dlp_tag() called")

    ################################################################################
    # Another dispatch playbooks with DLP tag
    ################################################################################

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/noop", parameters=parameters, name="another_dispatch_playbooks_with_dlp_tag")

    return


@phantom.playbook_block()
def playbook_dispatch_playbooks_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_dispatch_playbooks_2() called")

    get_playbook_name__playbook_name = json.loads(_ if (_ := phantom.get_run_data(key="get_playbook_name:playbook_name")) != "" else "null")  # pylint: disable=used-before-assignment

    inputs = {
        "playbook_tags": ["enrichment"],
        "playbook_name": get_playbook_name__playbook_name,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "es8_risk_findings_response/dispatch_playbooks", returns the playbook_run_id
    playbook_run_id = phantom.playbook("es8_risk_findings_response/dispatch_playbooks", container=container, name="playbook_dispatch_playbooks_2", callback=playbook_dispatch_playbooks_2_callback, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_dispatch_playbooks_2_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_dispatch_playbooks_2_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return