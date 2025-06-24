"""
An alternative to the included playbook block that collects indicator type data from the container and routes it to available input playbooks based on provided criteria. It will pair indicator data with the playbook&#39;s inputs based on the data type.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'check_valid_inputs' block
    check_valid_inputs(container=container)

    return

@phantom.playbook_block()
def dispatch_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("dispatch_playbooks() called")

    ################################################################################
    # Dynamically routes indicator types to playbook inputs based on  playbook input_spec 
    # and generates a list of playbook IDs and names to check downstream.
    ################################################################################

    playbook_input_playbook_name = phantom.collect2(container=container, datapath=["playbook_input:playbook_name"])

    playbook_input_playbook_name_values = [item[0] for item in playbook_input_playbook_name]

    dispatch_playbooks__names = None
    dispatch_playbooks__ids = None

    ################################################################################
    ## Custom Code Start
    ################################################################################


    playbook_launch_list = {}
    dispatch_playbooks__names = []
    dispatch_playbooks__ids = []

    phantom.debug(playbook_input_playbook_name_values)
    for pb_name in playbook_input_playbook_name_values:
        playbook_launch_list[pb_name] = pb_name

    if playbook_launch_list:
        for k,v in playbook_launch_list.items():
            name = 'playbook_{}'.format(k.split('/')[1].replace(' ','_').lower())
            dispatch_playbooks__names.append(name)
            phantom.debug(f"Launching playbook '{k}'")
            dispatch_playbooks__ids.append(phantom.playbook(playbook=k, container=container, name=name, callback=wait_for_playbooks))
            
    else:
        raise RuntimeError(f"""Unable to find any playbooks in the response plan""")
        
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="dispatch_playbooks__inputs:0:playbook_input:playbook_name", value=json.dumps(playbook_input_playbook_name_values))

    phantom.save_block_result(key="dispatch_playbooks:names", value=json.dumps(dispatch_playbooks__names))
    phantom.save_block_result(key="dispatch_playbooks:ids", value=json.dumps(dispatch_playbooks__ids))

    wait_for_playbooks(container=container)

    return


@phantom.playbook_block()
def wait_for_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("wait_for_playbooks() called")

    ################################################################################
    # Waits for all of the playbooks from the preceding block to finish.
    ################################################################################

    dispatch_playbooks__names = json.loads(_ if (_ := phantom.get_run_data(key="dispatch_playbooks:names")) != "" else "null")  # pylint: disable=used-before-assignment

    ################################################################################
    ## Custom Code Start
    ################################################################################

    if phantom.completed(playbook_names=dispatch_playbooks__names):
        #process_outputs(container=container)
        phantom.debug("playbooks have been executed")
    # return early to avoid moving to next block
    return    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="wait_for_playbooks__inputs:0:dispatch_playbooks:custom_function:names", value=json.dumps(dispatch_playbooks__names))

    return


@phantom.playbook_block()
def check_valid_inputs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_valid_inputs() called")

    ################################################################################
    # Check playbook inputs and produce associated errors
    ################################################################################

    playbook_input_playbook_tags = phantom.collect2(container=container, datapath=["playbook_input:playbook_tags"])
    playbook_input_playbook_name = phantom.collect2(container=container, datapath=["playbook_input:playbook_name"])

    playbook_input_playbook_tags_values = [item[0] for item in playbook_input_playbook_tags]
    playbook_input_playbook_name_values = [item[0] for item in playbook_input_playbook_name]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    # Check for at least 1 playbook_tag
    if not playbook_input_playbook_tags_values or not any(playbook_input_playbook_tags_values):
        raise ValueError("Must provide at least 1 playbook tag value to find available playbooks")
    
    if not playbook_input_playbook_name_values or not any(playbook_input_playbook_name_values):
        raise ValueError("Must provide at least 1 playbook Name to find available playbooks")
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="check_valid_inputs__inputs:0:playbook_input:playbook_tags", value=json.dumps(playbook_input_playbook_tags_values))
    phantom.save_block_result(key="check_valid_inputs__inputs:1:playbook_input:playbook_name", value=json.dumps(playbook_input_playbook_name_values))

    decision_3(container=container)

    return


@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["enrichment", "in", "playbook_input:playbook_tags"]
        ],
        conditions_dps=[
            ["enrichment", "in", "playbook_input:playbook_tags"]
        ],
        name="decision_3:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        dispatch_playbooks(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    output = {
        "verdict": [],
        "sub_playbook_outputs": [],
        "sub_playbook_inputs": [],
        "playbook_run_id_list": [],
        "playbook_id_list": [],
        "playbook_name_list": [],
        "observable": [],
        "markdown_report": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    # If certain outputs should appear, put those into the End block, but do not 
    # populate them. The process_outputs block will handle passing those outputs 
    # forward if they exist in the child playbooks.
    
    # Overwrite output with outputs generated in process_outputs.
    #process_outputs__data = phantom.get_run_data(key="process_outputs:data")
    
    #if process_outputs__data: 
    #    output = json.loads(process_outputs__data)
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return