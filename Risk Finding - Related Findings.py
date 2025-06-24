"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    # call 'refresh_finding_or_investigation_1' block
    get_finding_or_investigation_1(container=container)
    return

@phantom.playbook_block()
def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""`notable` | where event_id IN ({0})\n| fields rule_name, event_id, status_label, owner""",
        parameters=[
            "included_findings:custom_function:finding_id"
        ])

    included_findings__finding_id = json.loads(_ if (_ := phantom.get_run_data(key="included_findings:finding_id")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if query_formatted_string is not None:
        parameters.append({
            "query": query_formatted_string,
            "command": "",
            "display": "rule_name, status_label, owner",
            "end_time": "",
            "start_time": "",
            "search_mode": "verbose",
            "attach_result": False,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["es"], callback=get_phase_id_1)

    return


@phantom.playbook_block()
def close_findings_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("close_findings_prompt() called")

    # set approver and message variables for phantom.prompt call

    user = phantom.collect2(container=container, datapath=["playbook:launching_user.name"])[0][0]
    role = None
    message = """This Investigation is composed of many related findings and intermediate findings.\n\nYou can browse all these related findings on a risk timeline in the Overview Tab.\n\nPlease select a response below to manage these findings in the Analyst Queue while you continue to work on the investigation.\n\n\n\n{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "findings_status_eval:custom_function:open_findings_note"
    ]

    # responses
    response_types = [
        {
            "prompt": "Do you want to close these individual findings?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=360, name="close_findings_prompt", parameters=parameters, response_types=response_types, callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["close_findings_prompt:action_result.summary.responses.0", "==", "Yes"]
        ],
        conditions_dps=[
            ["close_findings_prompt:action_result.summary.responses.0", "==", "Yes"]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        open_finding_ids(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def add_task_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""Based on the positive response of the user prompt to close findings, all related findings have been closed in the Analyst Queue with Disposition as \"Closed - As part of investigation\". The context of all those individual findings is available in this investigation.\n\n{0}\n\n\nThere may be other \"Intermediate Findings\" contributing to this investigation, please review them in the Overview tab""",
        parameters=[
            "open_findings_1:formatted_data"
        ])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    open_findings_1 = phantom.get_format_data(name="open_findings_1")

    parameters = []

    # build parameters list for 'add_task_note_2' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if get_finding_or_investigation_1_result_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_finding_or_investigation_1_result_item[0],
                        "title": "Analyst decision to close related findings",
                        "content": content_formatted_string,
                        "task_id": get_task_id_1_result_item[0],
                        "phase_id": get_phase_id_1_result_item[0],
                        "response_plan_id": get_finding_or_investigation_1_result_item[1],
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_2", assets=["builtin_mc_connector"], callback=update_task_in_current_phase_1)

    return


@phantom.playbook_block()
def update_task_in_current_phase_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_task_in_current_phase_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'update_task_in_current_phase_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            if get_finding_or_investigation_1_result_item[0] is not None and get_task_id_1_result_item[0] is not None:
                parameters.append({
                    "id": get_finding_or_investigation_1_result_item[0],
                    "name": "Gather related findings",
                    "order": "",
                    "status": "Ended",
                    "task_id": get_task_id_1_result_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update task in current phase", parameters=parameters, name="update_task_in_current_phase_1", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def get_phase_id_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_phase_id_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.name","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_phase_id_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
                "phase_name": "Preprocess",
                "response_template_name": get_finding_or_investigation_1_result_item[1],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get phase id", parameters=parameters, name="get_phase_id_1", assets=["builtin_mc_connector"], callback=get_task_id_1)

    return


@phantom.playbook_block()
def get_task_id_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_task_id_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.name","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_task_id_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
                "task_name": "Gather related findings",
                "phase_name": "Preprocess",
                "response_template_name": get_finding_or_investigation_1_result_item[1],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get task id", parameters=parameters, name="get_task_id_1", assets=["builtin_mc_connector"], callback=update_task_in_current_phase_2)

    return


@phantom.playbook_block()
def get_finding_or_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_finding_or_investigation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id"])

    parameters = []

    # build parameters list for 'get_finding_or_investigation_1' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None:
            parameters.append({
                "id": finding_data_item[0],
                "finding_time": "",
                "map_consolidated_findings": 1,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get finding or investigation", parameters=parameters, name="get_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=included_findings)

    return


@phantom.playbook_block()
def update_task_in_current_phase_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_task_in_current_phase_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'update_task_in_current_phase_2' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            if get_finding_or_investigation_1_result_item[0] is not None and get_task_id_1_result_item[0] is not None:
                parameters.append({
                    "id": get_finding_or_investigation_1_result_item[0],
                    "name": "Gather related findings",
                    "status": "Started",
                    "task_id": get_task_id_1_result_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update task in current phase", parameters=parameters, name="update_task_in_current_phase_2", assets=["builtin_mc_connector"], callback=findings_status_eval)

    return


@phantom.playbook_block()
def included_findings(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("included_findings() called")

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.consolidated_findings_map._raw"], action_results=results)

    get_finding_or_investigation_1_result_item_0 = [item[0] for item in get_finding_or_investigation_1_result_data]

    included_findings__finding_id = None
    included_findings__intermediate_finding_id = None
    included_findings__findings_list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug(get_finding_or_investigation_1_result_item_0)
    #phantom.debug(type(get_finding_or_investigation_1_result_item_0))
    import json
    import re

    included_findings__finding_id = []
    included_findings__intermediate_finding_id = []
    final_result = {
        "finding_ids": [],
        "intermediate_finding_ids": []
    }

    # Loop through each dictionary in the list
    for item in get_finding_or_investigation_1_result_item_0:
        for long_key_string in item.keys():
            matches = re.findall(r'(\w+)="(.*?)"', long_key_string)
            for key, value in matches:
                if key in ["finding_ids", "intermediate_finding_ids"]:
                    final_result[key].append(value)

    included_findings__findings_list = final_result["finding_ids"]
    included_findings__finding_id = final_result["finding_ids"]
    included_findings__intermediate_finding_id = final_result["intermediate_finding_ids"]
    
    included_findings__finding_id = str(included_findings__finding_id).replace("[","").replace("]","").replace("'","\"")
    included_findings__intermediate_finding_id = str(included_findings__intermediate_finding_id).replace("[","").replace("]","").replace("'","\"")
    
    phantom.debug(included_findings__finding_id)
    phantom.debug(included_findings__intermediate_finding_id)
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="included_findings__inputs:0:get_finding_or_investigation_1:action_result.data.*.consolidated_findings_map._raw", value=json.dumps(get_finding_or_investigation_1_result_item_0))

    phantom.save_block_result(key="included_findings:finding_id", value=json.dumps(included_findings__finding_id))
    phantom.save_block_result(key="included_findings:intermediate_finding_id", value=json.dumps(included_findings__intermediate_finding_id))
    phantom.save_block_result(key="included_findings:findings_list", value=json.dumps(included_findings__findings_list))

    run_query_1(container=container)

    return


@phantom.playbook_block()
def update_event_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_event_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    open_finding_ids__result = phantom.collect2(container=container, datapath=["open_finding_ids:custom_function_result.data.output"])

    parameters = []

    # build parameters list for 'update_event_1' call
    for open_finding_ids__result_item in open_finding_ids__result:
        if open_finding_ids__result_item[0] is not None:
            parameters.append({
                "status": 5,
                "event_ids": open_finding_ids__result_item[0],
                "disposition": "",
                "integer_disposition": 7,
                "wait_for_confirmation": True,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="update_event_1", assets=["es"], callback=decision_2)

    return


@phantom.playbook_block()
def add_task_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""Findings that are already Closed Findings and are related to this investigation:\n\n{0}""",
        parameters=[
            "closed_findings:formatted_data"
        ])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    closed_findings = phantom.get_format_data(name="closed_findings")

    parameters = []

    # build parameters list for 'add_task_note_3' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if get_finding_or_investigation_1_result_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_finding_or_investigation_1_result_item[0],
                        "title": "Closed Findings",
                        "content": content_formatted_string,
                        "task_id": get_task_id_1_result_item[0],
                        "phase_id": get_phase_id_1_result_item[0],
                        "response_plan_id": get_finding_or_investigation_1_result_item[1],
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_3", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def open_findings_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("open_findings_1() called")

    template = """| Detection | Finding | Old Status | New Status | Owner |\n| --- | --- | --- | --- | --- |\n%%\n| {0} | [{1}](https://i-0e6bc36a44836889b.splunk.show/en-GB/app/SplunkEnterpriseSecuritySuite/incident_review?earliest=-30d&latest=now&event_id={1}) | {2} | Closed | {3} |\n%%\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "findings_status_eval:custom_function:open_finding_rule_name",
        "findings_status_eval:custom_function:open_finding_ids",
        "findings_status_eval:custom_function:open_finding_status",
        "findings_status_eval:custom_function:open_finding_owner"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="open_findings_1")

    add_task_note_2(container=container)

    return


@phantom.playbook_block()
def closed_findings(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("closed_findings() called")

    template = """| Detection | Finding | Status | Owner |\n| --- | --- | --- | --- |\n%%\n| {0} | [{1}](https://i-0e6bc36a44836889b.splunk.show/en-GB/app/SplunkEnterpriseSecuritySuite/incident_review?earliest=-30d&latest=now&search={1}) | {2} | {3} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "findings_status_eval:custom_function:closed_finding_rule_name",
        "findings_status_eval:custom_function:closed_finding_ids",
        "findings_status_eval:custom_function:closed_finding_status",
        "findings_status_eval:custom_function:closed_finding_owner"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="closed_findings")

    add_task_note_3(container=container)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["update_event_1:action_result.status", "==", "success"]
        ],
        conditions_dps=[
            ["update_event_1:action_result.status", "==", "success"]
        ],
        name="decision_2:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        open_findings_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def findings_status_eval(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("findings_status_eval() called")

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data.*.rule_name","run_query_1:action_result.data.*.event_id","run_query_1:action_result.data.*.status_label","run_query_1:action_result.data.*.owner"], action_results=results)

    run_query_1_result_item_0 = [item[0] for item in run_query_1_result_data]
    run_query_1_result_item_1 = [item[1] for item in run_query_1_result_data]
    run_query_1_result_item_2 = [item[2] for item in run_query_1_result_data]
    run_query_1_result_item_3 = [item[3] for item in run_query_1_result_data]

    findings_status_eval__open_findings_note = None
    findings_status_eval__open_finding_ids = None
    findings_status_eval__open_finding_rule_name = None
    findings_status_eval__open_finding_status = None
    findings_status_eval__open_finding_owner = None
    findings_status_eval__closed_findings_note = None
    findings_status_eval__closed_finding_ids = None
    findings_status_eval__closed_finding_rule_name = None
    findings_status_eval__closed_finding_status = None
    findings_status_eval__closed_finding_owner = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    findings_status_eval__open_finding_ids = []
    findings_status_eval__open_finding_rule_name = []
    findings_status_eval__open_finding_status = []
    findings_status_eval__open_finding_owner = []
    
    findings_status_eval__closed_finding_ids = []
    findings_status_eval__closed_finding_rule_name = []
    findings_status_eval__closed_finding_status = []
    findings_status_eval__closed_finding_owner = []


    if run_query_1_result_data:
        note_open = (
            "\n**Below are the list of open findings related to this investigation.**\n"
            "| Rule name | Finding | Status | Owner |\n"
            "| :--- | :--- | :--- | :--- |\n"
        )
        note_closed = (
            "\n**Below are the list of already findings related to this investigation.**\n"
            "| Rule name | Finding | Status | Owner |\n"
            "| :--- | :--- | :--- | :--- |\n"
        )

        for rule_name,event_id,status,owner in zip(run_query_1_result_item_0,run_query_1_result_item_1,run_query_1_result_item_2,run_query_1_result_item_3):
            #rule_name = rule_name.replace('\n','')
            #event_id = event_id.replace('\n','')
            finding_url = "https://i-0e6bc36a44836889b.splunk.show/en-GB/app/SplunkEnterpriseSecuritySuite/incident_review?earliest=-30d&latest=now&event_id=" + event_id
            #status = status.replace('\n','')
            #owner = owner.replace('\n','')
            if status not in ('Closed', 'Resolved'):
                note_open += "|{}|[{}]({})|{}|{}|\n".format(rule_name, event_id, finding_url, status, owner)
                findings_status_eval__open_finding_ids.append(event_id)
                findings_status_eval__open_finding_rule_name.append(rule_name)
                findings_status_eval__open_finding_status.append(status)
                findings_status_eval__open_finding_owner.append(owner)
            if status in ('Closed', 'Resolved'):
                note_closed += "|{}|[{}]({})|{}|{}|\n".format(rule_name, event_id, finding_url, status, owner)
                findings_status_eval__closed_finding_ids.append(event_id)
                findings_status_eval__closed_finding_rule_name.append(rule_name)
                findings_status_eval__closed_finding_status.append(status)
                findings_status_eval__closed_finding_owner.append(owner)

        findings_status_eval__open_findings_note = note_open
        findings_status_eval__closed_findings_note = note_closed
        
    else:
        findings_status_eval__open_findings_note = "\n\n**No open findings found in the investigation in last 30 days**\n"    
        findings_status_eval__closed_findings_note = "\n\n**No closed findings found in the investigation in last 30 days**\n"    


    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="findings_status_eval__inputs:0:run_query_1:action_result.data.*.rule_name", value=json.dumps(run_query_1_result_item_0))
    phantom.save_block_result(key="findings_status_eval__inputs:1:run_query_1:action_result.data.*.event_id", value=json.dumps(run_query_1_result_item_1))
    phantom.save_block_result(key="findings_status_eval__inputs:2:run_query_1:action_result.data.*.status_label", value=json.dumps(run_query_1_result_item_2))
    phantom.save_block_result(key="findings_status_eval__inputs:3:run_query_1:action_result.data.*.owner", value=json.dumps(run_query_1_result_item_3))

    phantom.save_block_result(key="findings_status_eval:open_findings_note", value=json.dumps(findings_status_eval__open_findings_note))
    phantom.save_block_result(key="findings_status_eval:open_finding_ids", value=json.dumps(findings_status_eval__open_finding_ids))
    phantom.save_block_result(key="findings_status_eval:open_finding_rule_name", value=json.dumps(findings_status_eval__open_finding_rule_name))
    phantom.save_block_result(key="findings_status_eval:open_finding_status", value=json.dumps(findings_status_eval__open_finding_status))
    phantom.save_block_result(key="findings_status_eval:open_finding_owner", value=json.dumps(findings_status_eval__open_finding_owner))
    phantom.save_block_result(key="findings_status_eval:closed_findings_note", value=json.dumps(findings_status_eval__closed_findings_note))
    phantom.save_block_result(key="findings_status_eval:closed_finding_ids", value=json.dumps(findings_status_eval__closed_finding_ids))
    phantom.save_block_result(key="findings_status_eval:closed_finding_rule_name", value=json.dumps(findings_status_eval__closed_finding_rule_name))
    phantom.save_block_result(key="findings_status_eval:closed_finding_status", value=json.dumps(findings_status_eval__closed_finding_status))
    phantom.save_block_result(key="findings_status_eval:closed_finding_owner", value=json.dumps(findings_status_eval__closed_finding_owner))

    close_findings_prompt(container=container)
    closed_findings(container=container)

    return


@phantom.playbook_block()
def open_finding_ids(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("open_finding_ids() called")

    findings_status_eval__open_finding_ids = json.loads(_ if (_ := phantom.get_run_data(key="findings_status_eval:open_finding_ids")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "input_list": findings_status_eval__open_finding_ids,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="open_finding_ids", callback=update_event_1)

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