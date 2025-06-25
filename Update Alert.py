"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'notable_status' block
    notable_status(container=container)

    return

@phantom.playbook_block()
def notable_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("notable_status() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_input:status_label", "==", "New"]
        ],
        conditions_dps=[
            ["playbook_input:status_label", "==", "New"]
        ],
        name="notable_status:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        decide_analyst(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    decide_disposition(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def decide_analyst(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decide_analyst() called")

    decide_analyst__analyst = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    import random
    
    try:
        # Attempt to convert the input to an integer for numerical comparisons
        random1 = random.randint(1, 10)
        
        # Apply the conditional logic to set the analyst
        if random1 < 5:
            decide_analyst__analyst = "jaejun@cisco.com"
        elif random1 == 5:
            decide_analyst__analyst = "dluxton@splunk.com"
        elif 6 <= random1 <= 7: # Checks if random1 is 6 or 7
            decide_analyst__analyst = "alice"
        elif random1 == 8:
            decide_analyst__analyst = "jaejun@cisco.com"
        elif random1 == 9:
            decide_analyst__analyst = "jitaror@cisco.com"
        else:
            # Handle cases where random1 is outside the specified range (e.g., > 9 or < 0)
            decide_analyst__analyst = "unassigned" # Assign a default or error value
            
    except (TypeError, ValueError) as e:
        # Handle cases where the input 'random1' is not a valid integer
        phantom.debug(f"Error: {e}")
        decide_analyst__analyst = "input_error" # Assign an error value if input is invalid

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="decide_analyst:analyst", value=json.dumps(decide_analyst__analyst))

    debug_2(container=container)

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
def debug_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_2() called")

    decide_analyst__analyst = json.loads(_ if (_ := phantom.get_run_data(key="decide_analyst:analyst")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "input_1": decide_analyst__analyst,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_2", callback=update_alert_in_progress)

    return


@phantom.playbook_block()
def update_alert_closed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_alert_closed() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    comment_formatted_string = phantom.format(
        container=container,
        template="""This one is a {0}\n{1}\n""",
        parameters=[
            "decide_disposition:custom_function:disposition",
            "playbook_input:owner"
        ])

    playbook_input_event_id = phantom.collect2(container=container, datapath=["playbook_input:event_id"])
    playbook_input_owner = phantom.collect2(container=container, datapath=["playbook_input:owner"])
    decide_disposition__disposition = json.loads(_ if (_ := phantom.get_run_data(key="decide_disposition:disposition")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'update_alert_closed' call
    for playbook_input_event_id_item in playbook_input_event_id:
        for playbook_input_owner_item in playbook_input_owner:
            if playbook_input_event_id_item[0] is not None:
                parameters.append({
                    "event_ids": playbook_input_event_id_item[0],
                    "status": "closed",
                    "comment": comment_formatted_string,
                    "disposition": decide_disposition__disposition,
                    "integer_status": "",
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="update_alert_closed", assets=["es"])

    return


@phantom.playbook_block()
def decide_disposition(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decide_disposition() called")

    decide_disposition__disposition = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    import random
    
    try:
        # Attempt to convert the input to an integer for numerical comparisons
        random1 = random.randint(1, 10)
        
        # Apply the conditional logic to set the analyst
        if random1 < 5:
            decide_disposition__disposition = "Benign Positive - Suspicious But Expected"
        elif random1 == 5:
            decide_disposition__disposition = "True Positive - Suspicious Activity"
        elif 6 <= random1 <= 7: # Checks if random1 is 6 or 7
            decide_disposition__disposition = "False Positive - Incorrect Analytic Logic"
        elif random1 == 8:
            decide_disposition__disposition = "False Positive - Inaccurate Data"
        elif random1 == 9:
            decide_disposition__disposition = "Other"
        else:
            # Handle cases where random1 is outside the specified range (e.g., > 9 or < 0)
            decide_disposition__disposition = "Other" # Assign a default or error value
            
    except (TypeError, ValueError) as e:
        # Handle cases where the input 'random1' is not a valid integer
        phantom.debug(f"Error: {e}")
        decide_disposition__disposition = "Other" # Assign an error value if input is invalid


    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="decide_disposition:disposition", value=json.dumps(decide_disposition__disposition))

    update_alert_closed(container=container)

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