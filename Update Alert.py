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
        conditions=[
            ["playbook_input:status_label", "==", "New"]
        ],
        conditions_dps=[
            ["playbook_input:status_label", "==", "New"]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        decide_analyst(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def decide_analyst(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decide_analyst() called")

    input_parameter_0 = "random1"

    decide_analyst__analyst = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    
    try:
        # Attempt to convert the input to an integer for numerical comparisons
        random1 = int(input_parameter_0)
        
        # Apply the conditional logic to set the analyst
        if random1 < 5:
            code_1__analyst = "alice"
        elif random1 == 5:
            code_1__analyst = "dluxton@splunk.com"
        elif 6 <= random1 <= 7: # Checks if random1 is 6 or 7
            code_1__analyst = "damo"
        elif random1 == 8:
            code_1__analyst = "fyodor"
        elif random1 == 9:
            code_1__analyst = "wally"
        else:
            # Handle cases where random1 is outside the specified range (e.g., > 9 or < 0)
            phantom.debug(f"Input '{input_parameter_0}' value ({random1}) is outside the defined assignment range (0-9).")
            code_1__analyst = "unassigned_analyst" # Assign a default or error value
            
    except (TypeError, ValueError) as e:
        # Handle cases where the input 'random1' is not a valid integer
        phantom.debug(f"Error: Input '{input_parameter_0}' is not a valid integer. Received: '{input_parameter_0}'. Error: {e}")
        code_1__analyst = "input_error" # Assign an error value if input is invalid

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="decide_analyst__inputs:0:random1", value=json.dumps("random1"))

    phantom.save_block_result(key="decide_analyst:analyst", value=json.dumps(decide_analyst__analyst))

    update_alert_in_progress(container=container)

    return


@phantom.playbook_block()
def update_alert_in_progress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_alert_in_progress() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    comment_formatted_string = phantom.format(
        container=container,
        template="""Investigating this one now. \n{0}\n""",
        parameters=[
            "decide_analyst:custom_function:analyst"
        ])

    playbook_input_event_id = phantom.collect2(container=container, datapath=["playbook_input:event_id"])
    decide_analyst__analyst = json.loads(_ if (_ := phantom.get_run_data(key="decide_analyst:analyst")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'update_alert_in_progress' call
    for playbook_input_event_id_item in playbook_input_event_id:
        if playbook_input_event_id_item[0] is not None:
            parameters.append({
                "event_ids": playbook_input_event_id_item[0],
                "owner": decide_analyst__analyst,
                "status": "",
                "integer_status": 2,
                "comment": comment_formatted_string,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="update_alert_in_progress", assets=["es"])

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