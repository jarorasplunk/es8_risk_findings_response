"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_finding_or_investigation_1' block
    get_finding_or_investigation_1(container=container)

    return

@phantom.playbook_block()
def update_finding_or_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_finding_or_investigation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    select_owner_result_data = phantom.collect2(container=container, datapath=["select_owner:action_result.summary.responses.0","select_owner:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'update_finding_or_investigation_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for select_owner_result_item in select_owner_result_data:
            if get_finding_or_investigation_1_result_item[0] is not None:
                parameters.append({
                    "id": get_finding_or_investigation_1_result_item[0],
                    "owner": select_owner_result_item[0],
                    "status": "In Progress",
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update finding or investigation", parameters=parameters, name="update_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=update_task_in_current_phase_1)

    return


@phantom.playbook_block()
def all_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("all_users() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "query": "/services/authentication/users |fields title roles realname|rename title as userName|rename realname as Name | where match(roles,\"ess\")",
        "command": "| rest",
        "display": "userName, Name",
        "search_mode": "smart",
        "add_raw_field": True,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="all_users", assets=["es"], callback=current_user)

    return


@phantom.playbook_block()
def select_owner(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("select_owner() called")

    # set approver and message variables for phantom.prompt call

    user = phantom.collect2(container=container, datapath=["playbook:launching_user.name"])[0][0]
    role = None
    message = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "es_users_list:formatted_data"
    ]

    # responses
    response_types = [
        {
            "prompt": "Analyst Name (as copied from above)",
            "options": {
                "type": "message",
                "required": True,
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="select_owner", parameters=parameters, response_types=response_types, callback=update_finding_or_investigation_1)

    return


@phantom.playbook_block()
def es_users_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("es_users_list() called")

    template = """Copy the \"Username\" value from the below list and paste in the below input box to assign an owner to this Investigation:\n\n| Name | Username |\n| --- | --- |\n%%\n| {0} | {1} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "all_users:action_result.data.*.Name",
        "all_users:action_result.data.*.userName"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="es_users_list")

    get_phase_id_1(container=container)

    return


@phantom.playbook_block()
def assignment_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("assignment_decision() called")

    # set approver and message variables for phantom.prompt call

    user = phantom.collect2(container=container, datapath=["playbook:launching_user.name"])[0][0]
    role = None
    message = """Do you want to assign this investigation to yourself or to another team member?"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Owner:",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yourself",
                    "Other"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="assignment_decision", parameters=parameters, response_types=response_types, callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["assignment_decision:action_result.summary.responses.0", "==", "Yourself"]
        ],
        conditions_dps=[
            ["assignment_decision:action_result.summary.responses.0", "==", "Yourself"]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        update_finding_or_investigation_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["assignment_decision:action_result.summary.responses.0", "==", "Other"]
        ],
        conditions_dps=[
            ["assignment_decision:action_result.summary.responses.0", "==", "Other"]
        ],
        name="decision_1:condition_2",
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        select_owner(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def current_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("current_user() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "query": " /services/authentication/current-context | rename realname as Name, username as userName | fields Name, userName",
        "command": "|  rest",
        "display": "userName, Name",
        "search_mode": "smart",
        "add_raw_field": True,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="current_user", assets=["es"], callback=es_users_list)

    return


@phantom.playbook_block()
def update_finding_or_investigation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_finding_or_investigation_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    current_user_result_data = phantom.collect2(container=container, datapath=["current_user:action_result.data.*.userName","current_user:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'update_finding_or_investigation_2' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for current_user_result_item in current_user_result_data:
            if get_finding_or_investigation_1_result_item[0] is not None:
                parameters.append({
                    "id": get_finding_or_investigation_1_result_item[0],
                    "owner": current_user_result_item[0],
                    "status": "In Progress",
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update finding or investigation", parameters=parameters, name="update_finding_or_investigation_2", assets=["builtin_mc_connector"], callback=update_task_in_current_phase_2)

    return


@phantom.playbook_block()
def add_task_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""Follow the prompts to manage this Investigation's ownership and status.\n\nMessage prompt name: assignment_decision\n""",
        parameters=[])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_2_result_data = phantom.collect2(container=container, datapath=["get_task_id_2:action_result.data.*.task_id","get_task_id_2:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_2_result_item in get_task_id_2_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if get_finding_or_investigation_1_result_item[0] is not None and content_formatted_string is not None and get_task_id_2_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_finding_or_investigation_1_result_item[0],
                        "title": "User Response Required",
                        "content": content_formatted_string,
                        "task_id": get_task_id_2_result_item[0],
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_1", assets=["builtin_mc_connector"], callback=assignment_decision)

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

    phantom.act("get phase id", parameters=parameters, name="get_phase_id_1", assets=["builtin_mc_connector"], callback=get_task_id_2)

    return


@phantom.playbook_block()
def get_task_id_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_task_id_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.name","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_task_id_2' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
                "task_name": "Prepare the investigation",
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

    phantom.act("get task id", parameters=parameters, name="get_task_id_2", assets=["builtin_mc_connector"], callback=update_task_in_current_phase_3)

    return


@phantom.playbook_block()
def update_task_in_current_phase_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_task_in_current_phase_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_2_result_data = phantom.collect2(container=container, datapath=["get_task_id_2:action_result.data.*.task_id","get_task_id_2:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'update_task_in_current_phase_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_2_result_item in get_task_id_2_result_data:
            if get_finding_or_investigation_1_result_item[0] is not None and get_task_id_2_result_item[0] is not None:
                parameters.append({
                    "id": get_finding_or_investigation_1_result_item[0],
                    "name": "Prepare the investigation",
                    "status": "Ended",
                    "task_id": get_task_id_2_result_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update task in current phase", parameters=parameters, name="update_task_in_current_phase_1", assets=["builtin_mc_connector"], callback=refresh_finding_or_investigation_2)

    return


@phantom.playbook_block()
def update_task_in_current_phase_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_task_in_current_phase_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_2_result_data = phantom.collect2(container=container, datapath=["get_task_id_2:action_result.data.*.task_id","get_task_id_2:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'update_task_in_current_phase_2' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_2_result_item in get_task_id_2_result_data:
            if get_finding_or_investigation_1_result_item[0] is not None and get_task_id_2_result_item[0] is not None:
                parameters.append({
                    "id": get_finding_or_investigation_1_result_item[0],
                    "name": "Prepare the investigation",
                    "status": "Ended",
                    "task_id": get_task_id_2_result_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update task in current phase", parameters=parameters, name="update_task_in_current_phase_2", assets=["builtin_mc_connector"], callback=refresh_finding_or_investigation_3)

    return


@phantom.playbook_block()
def add_task_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""The investigation status has been changed to \"In Progress\" and it has been assigned to: {0}""",
        parameters=[
            "refresh_finding_or_investigation_3:action_result.data.*.data.owner"
        ])

    refresh_finding_or_investigation_3_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_3:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_3:action_result.data.*.data.owner","refresh_finding_or_investigation_3:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_2_result_data = phantom.collect2(container=container, datapath=["get_task_id_2:action_result.data.*.task_id","get_task_id_2:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_2' call
    for refresh_finding_or_investigation_3_result_item in refresh_finding_or_investigation_3_result_data:
        for get_task_id_2_result_item in get_task_id_2_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
                    if refresh_finding_or_investigation_3_result_item[0] is not None and content_formatted_string is not None and get_task_id_2_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[0] is not None:
                        parameters.append({
                            "id": refresh_finding_or_investigation_3_result_item[0],
                            "title": "Investigation assignment:",
                            "content": content_formatted_string,
                            "task_id": get_task_id_2_result_item[0],
                            "phase_id": get_phase_id_1_result_item[0],
                            "response_plan_id": get_finding_or_investigation_1_result_item[0],
                        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_2", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def refresh_finding_or_investigation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("refresh_finding_or_investigation_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'refresh_finding_or_investigation_2' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("refresh finding or investigation", parameters=parameters, name="refresh_finding_or_investigation_2", assets=["builtin_mc_connector"], callback=add_task_note_3)

    return


@phantom.playbook_block()
def refresh_finding_or_investigation_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("refresh_finding_or_investigation_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'refresh_finding_or_investigation_3' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("refresh finding or investigation", parameters=parameters, name="refresh_finding_or_investigation_3", assets=["builtin_mc_connector"], callback=add_task_note_2)

    return


@phantom.playbook_block()
def add_task_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""The investigation status has been changed to \"In Progress\" and it has been assigned to: {0}\n""",
        parameters=[
            "refresh_finding_or_investigation_2:action_result.data.*.data.owner"
        ])

    refresh_finding_or_investigation_2_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_2:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_2:action_result.data.*.data.owner","refresh_finding_or_investigation_2:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_2_result_data = phantom.collect2(container=container, datapath=["get_task_id_2:action_result.data.*.task_id","get_task_id_2:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_3' call
    for refresh_finding_or_investigation_2_result_item in refresh_finding_or_investigation_2_result_data:
        for get_task_id_2_result_item in get_task_id_2_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
                    if refresh_finding_or_investigation_2_result_item[0] is not None and content_formatted_string is not None and get_task_id_2_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[0] is not None:
                        parameters.append({
                            "id": refresh_finding_or_investigation_2_result_item[0],
                            "title": "Investigation assignment:",
                            "content": content_formatted_string,
                            "task_id": get_task_id_2_result_item[0],
                            "phase_id": get_phase_id_1_result_item[0],
                            "response_plan_id": get_finding_or_investigation_1_result_item[0],
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
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    refresh_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_1:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_1:action_result.data.*.data.response_plans.*.name","refresh_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    refresh_finding_or_investigation_1_result_item_0 = [item[0] for item in refresh_finding_or_investigation_1_result_data]
    refresh_finding_or_investigation_1_result_item_1 = [item[1] for item in refresh_finding_or_investigation_1_result_data]

    parameters = []

    parameters.append({
        "input_1": refresh_finding_or_investigation_1_result_item_0,
        "input_2": refresh_finding_or_investigation_1_result_item_1,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1")

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
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get finding or investigation", parameters=parameters, name="get_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=all_users)

    return


@phantom.playbook_block()
def update_task_in_current_phase_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_task_in_current_phase_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_2_result_data = phantom.collect2(container=container, datapath=["get_task_id_2:action_result.data.*.task_id","get_task_id_2:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'update_task_in_current_phase_3' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_2_result_item in get_task_id_2_result_data:
            if get_finding_or_investigation_1_result_item[0] is not None and get_task_id_2_result_item[0] is not None:
                parameters.append({
                    "id": get_finding_or_investigation_1_result_item[0],
                    "name": "Prepare the investigation",
                    "status": "Started",
                    "task_id": get_task_id_2_result_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update task in current phase", parameters=parameters, name="update_task_in_current_phase_3", assets=["builtin_mc_connector"], callback=add_task_note_1)

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