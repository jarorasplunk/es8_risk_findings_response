"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'create_response_plan_json' block
    create_response_plan_json(container=container)

    return

@phantom.playbook_block()
def create_response_plan_json(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_response_plan_json() called")

    create_response_plan_json__risk_findings_response_json_body = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    var_true = True
    var_false = False
    var_0 = 0
    var_1 = 1
    var_2 = 2
    var_3 = 3
    
    # Create JSON body for "Risk Notable Investigation" response plan
    
    create_response_plan_json__risk_findings_response_json_body = {
        "name": "Risk Findings Response 2",
        "version": "1",
        "is_default": var_false,
        "description": "A series of tasks for enrichment, investigation and response to incidents created by Risk Notables",
        "template_status": "published",
        "phases": [
            {
                "name": "Preprocess",
                "order": var_1,
                "tasks": [
                    {
                        "name": "Prepare the investigation",
                        "order": var_1,
                        "description": "In the right hand side panel of this investigation:\n1. Update the status of this investigation from New to In-Progress\n2. Assign the owner of this investigation\n3. Optional: Select a disposition, if it is applicable at this stage.\n\nAlternatively, run the playbook (below), which will:\n1. Assign the incident to you as an analyst\n2. Change the status from New to In-Progress",
                        "suggestions": {
                            "actions": [],
                            "searches": [],
                            "playbooks": [
                                {
                                    "name": "Risk Finding - Prepare Investigation",
                                    "scope": "all",
                                    "description": "Risk Finding - Prepare Investigation",
                                    "playbook_id": "es8_risk_findings_response/Risk Finding - Prepare Investigation",
                                    "last_job_id": var_0
                                }
                            ]
                        },
                        "is_note_required": var_false
                    },
                    {
                        "name": "Gather related findings",
                        "order": var_2,
                        "description": "Gather related individual findings and intermediate findings that are part of this investigation.\nRun the playbook (below) which will capture the related findings from the Analyst Queue and will provide you options to close the individual alerts/findings in the Analyst Queue, while you continue to work on this investigation.",
                        "suggestions": {
                            "actions": [],
                            "searches": [],
                            "playbooks": [
                                {
                                    "name": "Risk Finding - Related Findings",
                                    "scope": "all",
                                    "description": "Risk Finding - Related Findings",
                                    "playbook_id": "es8_risk_findings_response/Risk Finding - Related Findings",
                                    "last_job_id": var_0
                                }
                            ]
                        },
                        "is_note_required": var_false
                    },
                    {
                        "name": "Enrich findings",
                        "order": var_3,
                        "description": "This step will extract key entities, indicators and behaviour from the included findings in this investigation and will enrich their context using SOAR automation workflows. The enriched information for all applicable findings will be presented here in the form of notes.",
                        "suggestions": {
                            "actions": [],
                            "searches": [],
                            "playbooks": [
                                {
                                    "name": "Risk Finding - Dispatch Enrichment Playbooks",
                                    "scope": "all",
                                    "description": "Risk Finding - Dispatch Enrichment Playbooks",
                                    "playbook_id": "es8_risk_findings_response/Risk Finding - Dispatch Enrichment Playbooks",
                                    "last_job_id": var_0
                                }
                            ]
                        },
                        "is_note_required": var_false
                    },
                ]
            },
            {
                "name": "Investigate",
                "order": var_1,
                "tasks": [
                    {
                        "name": "Investigate findings",
                        "order": var_1,
                        "description": "Investigate individual findings in this Risk Investigation. An autoamted playbook has trigerred and captured additonal details about the individal findings, please review them and conduct further investigation.",
                        "suggestions": {
                            "actions": [],
                            "searches": [],
                            "playbooks": [
                                {
                                    "name": "Risk Finding - Investigate Findings",
                                    "scope": "all",
                                    "description": "Risk Finding - Investigate Findings",
                                    "playbook_id": "es8_risk_findings_response/Risk Finding - Investigate Findings",
                                    "last_job_id": var_0
                                }
                            ]
                        },
                        "is_note_required": var_false
                    },
                    {
                        "name": "Hunt Indicators",
                        "order": var_2,
                        "description": "Hunt for the involved indicators from this Risk Finding across Splunk logs. Gather evidence of presence of these indicators.",
                        "suggestions": {
                            "actions": [],
                            "searches": [],
                            "playbooks": [
                                {
                                    "name": "Risk Finding - Hunt Indicators",
                                    "scope": "all",
                                    "description": "Risk Finding - Hunt Indicators",
                                    "playbook_id": "es8_risk_findings_response/Risk Finding - Hunt Indicators",
                                    "last_job_id": var_0
                                }
                            ]
                        },
                        "is_note_required": var_false
                    },
                    {
                        "name": "Optional: Investigation notes",
                        "order": var_3,
                        "description": "Add any additional investigation details performed outside of this response plan. Create manual notes and attach files etc.",
                        "suggestions": {
                            "actions": [],
                            "searches": [],
                            "playbooks": []
                        },
                        "is_note_required": var_false
                    },
                ]
            }
        ]
    }
    
    
    convert_json_risk_findings_response = json.dumps(create_response_plan_json__risk_findings_response_json_body)
    phantom.debug(convert_json_risk_findings_response)
    create_response_plan_json__risk_findings_response_json_body = convert_json_risk_findings_response

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="create_response_plan_json:risk_findings_response_json_body", value=json.dumps(create_response_plan_json__risk_findings_response_json_body))

    post_data_1(container=container)

    return


@phantom.playbook_block()
def post_data_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("post_data_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    create_response_plan_json__risk_findings_response_json_body = json.loads(_ if (_ := phantom.get_run_data(key="create_response_plan_json:risk_findings_response_json_body")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "body": create_response_plan_json__risk_findings_response_json_body,
        "location": "/v1/responseplans",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("post data", parameters=parameters, name="post_data_1", assets=["es"])

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