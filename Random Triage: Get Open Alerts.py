"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'generate_random_number' block
    generate_random_number(container=container)

    return

@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["generate_random_number:custom_function:random1_odds", "<", 85]
        ],
        conditions_dps=[
            ["generate_random_number:custom_function:random1_odds", "<", 85]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        return

    # check for 'else' condition 2
    list_open_alerts(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def playbook_update_alert_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_update_alert_1() called")

    list_open_alerts_result_data = phantom.collect2(container=container, datapath=["list_open_alerts:action_result.data.*.items.*.event_id","list_open_alerts:action_result.data.*.items.*.owner","list_open_alerts:action_result.data.*.items.*.status_label","list_open_alerts:action_result.data.*.items.*.disposition_label"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.random1","artifact:*.cef.random2"])

    list_open_alerts_result_item_0 = [item[0] for item in list_open_alerts_result_data]
    list_open_alerts_result_item_1 = [item[1] for item in list_open_alerts_result_data]
    list_open_alerts_result_item_2 = [item[2] for item in list_open_alerts_result_data]
    list_open_alerts_result_item_3 = [item[3] for item in list_open_alerts_result_data]
    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_cef_item_1 = [item[1] for item in container_artifact_data]

    inputs = {
        "event_id": list_open_alerts_result_item_0,
        "owner": list_open_alerts_result_item_1,
        "status_label": list_open_alerts_result_item_2,
        "disposition_label": list_open_alerts_result_item_3,
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
def list_open_alerts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_open_alerts() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "limit": 4,
        "disposition": "Undetermined",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("list findings", parameters=parameters, name="list_open_alerts", assets=["builtin_mc_connector"], callback=playbook_update_alert_1)

    return


@phantom.playbook_block()
def generate_random_number(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("generate_random_number() called")

    generate_random_number__random1_odds = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    import random
    random1__random1 = random.randint(1, 100)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="generate_random_number:random1_odds", value=json.dumps(generate_random_number__random1_odds))

    debug_5(container=container)

    return


@phantom.playbook_block()
def debug_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_5() called")

    generate_random_number__random1_odds = json.loads(_ if (_ := phantom.get_run_data(key="generate_random_number:random1_odds")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "input_1": generate_random_number__random1_odds,
        "input_2": None,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_5")

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