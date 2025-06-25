"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'decision_1' block
    decision_1(container=container)

    return

@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["artifact:*.cef.random1_odds", "==", True],
            ["artifact:*.cef.random2_oods", "==", True]
        ],
        conditions_dps=[
            ["artifact:*.cef.random1_odds", "==", True],
            ["artifact:*.cef.random2_oods", "==", True]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        return

    # check for 'else' condition 2
    get_open_alerts(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def get_open_alerts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_open_alerts() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "command": "search",
        "search_mode": "smart",
        "add_raw_field": True,
        "query": "(515f9487-1993-43a0-b416-db3e4593d2fa@@notable@@515f9487199343a0b416db3e4593d2fa OR 047ca399-3872-4155-a045-f1ad49ce0ef3@@notable@@047ca39938724155a045f1ad49ce0ef3)  detection_type=ebd `notable` | where status_end=\"false\" | table event_id owner status* disposition*",
        "display": "event_id,owner, status_label, disposition_label",
        "start_time": "-24h",
        "end_time": "now",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="get_open_alerts", assets=["es"], callback=playbook_update_alert_1)

    return


@phantom.playbook_block()
def playbook_update_alert_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_update_alert_1() called")

    get_open_alerts_result_data = phantom.collect2(container=container, datapath=["get_open_alerts:action_result.data.*.event_id","get_open_alerts:action_result.data.*.owner","get_open_alerts:action_result.data.*.status_label","get_open_alerts:action_result.data.*.disposition_label"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.random1","artifact:*.cef.random2"])

    get_open_alerts_result_item_0 = [item[0] for item in get_open_alerts_result_data]
    get_open_alerts_result_item_1 = [item[1] for item in get_open_alerts_result_data]
    get_open_alerts_result_item_2 = [item[2] for item in get_open_alerts_result_data]
    get_open_alerts_result_item_3 = [item[3] for item in get_open_alerts_result_data]
    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_cef_item_1 = [item[1] for item in container_artifact_data]

    inputs = {
        "event_id": get_open_alerts_result_item_0,
        "owner": get_open_alerts_result_item_1,
        "status_label": get_open_alerts_result_item_2,
        "disposition_label": get_open_alerts_result_item_3,
        "random1": container_artifact_cef_item_0,
        "random2": container_artifact_cef_item_1,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "es8_risk_findings_response/Update Alert", returns the playbook_run_id
    playbook_run_id = phantom.playbook("es8_risk_findings_response/Update Alert", container=container, inputs=inputs)

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