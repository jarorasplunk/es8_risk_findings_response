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
        format_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    run_query_1(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def playbook_update_alert_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_update_alert_1() called")

    regex_split_5_data = phantom.collect2(container=container, datapath=["regex_split_5:custom_function_result.data.*.item"])

    regex_split_5_data___item = [item[0] for item in regex_split_5_data]

    inputs = {
        "event_id": regex_split_5_data___item,
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

    join_close_container(container=container)

    return


@phantom.playbook_block()
def generate_random_number(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("generate_random_number() called")

    generate_random_number__random1_odds = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    import random
    generate_random_number__random1_odds = random.randint(1, 100)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="generate_random_number:random1_odds", value=json.dumps(generate_random_number__random1_odds))

    decision_1(container=container)

    return


@phantom.playbook_block()
def join_close_container(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_close_container() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_close_container_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_block_result(key="join_close_container_called", value="close_container")

    # call connected block "close_container"
    close_container(container=container, handle=handle)

    return


@phantom.playbook_block()
def close_container(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("close_container() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="closed")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_1() called")

    template = """Random number {0} did not trigger any auto triage this time.  \n"""

    # parameter list for template variable replacement
    parameters = [
        "generate_random_number:custom_function:random1_odds"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    add_comment_4(container=container)

    return


@phantom.playbook_block()
def add_comment_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_4() called")

    format_1 = phantom.get_format_data(name="format_1")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_1)

    join_close_container(container=container)

    return


@phantom.playbook_block()
def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "query": "detection_type=ebd source!=\"ESCU - Malicious PowerShell Process - Encoded Command - Rule\" `notable` | where status_end=\"false\" | tail 4 | stats values(event_id) as event_id  | nomv event_id",
        "command": "search",
        "display": "event_id",
        "end_time": "-15m",
        "start_time": "-24h",
        "search_mode": "smart",
        "add_raw_field": False,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["es"], callback=regex_split_5)

    return


@phantom.playbook_block()
def regex_split_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("regex_split_5() called")

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data.*.event_id","run_query_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'regex_split_5' call
    for run_query_1_result_item in run_query_1_result_data:
        parameters.append({
            "regex": " ",
            "input_string": run_query_1_result_item[0],
            "strip_whitespace": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/regex_split", parameters=parameters, name="regex_split_5", callback=playbook_update_alert_1)

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