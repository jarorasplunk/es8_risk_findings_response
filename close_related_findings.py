"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'update_finding_or_investigation_1' block
    update_finding_or_investigation_1(container=container)

    return

@phantom.playbook_block()
def update_finding_or_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_finding_or_investigation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_findings_list = phantom.collect2(container=container, datapath=["playbook_input:findings_list"])

    parameters = []

    # build parameters list for 'update_finding_or_investigation_1' call
    for playbook_input_findings_list_item in playbook_input_findings_list:
        if playbook_input_findings_list_item[0] is not None:
            parameters.append({
                "id": playbook_input_findings_list_item[0],
                "disposition": "disposition:7",
                "status": "Closed",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    parameters = []
    phantom.debug(playbook_input_findings_list)
    
    for item in playbook_input_findings_list:
        phantom.debug(item[0])
        parameters.append({
            "id": item[0],
            "status": "Closed",
            "disposition": "disposition:7",
        })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update finding or investigation", parameters=parameters, name="update_finding_or_investigation_1", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    update_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["update_finding_or_investigation_1:action_result.data.*.id"])

    update_finding_or_investigation_1_result_item_0 = [item[0] for item in update_finding_or_investigation_1_result_data]

    output = {
        "status": update_finding_or_investigation_1_result_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return