from typing import List
import logging
import requests
import argparse
import base64

def create_rbac_role_with_permissions(
    airflow_url: str, 
    new_role_name: str, 
    dag_names: List[str],
    google_access_token: str=None,
    airflow_username: str=None,
    airflow_password: str=None
):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    if google_access_token:
        headers["Authorization"] = "Bearer " + google_access_token
    elif airflow_username and airflow_password:
        auth_str = f"{airflow_username}:{airflow_password}"
        base64_auth_str = base64.b64encode(auth_str.encode()).decode()
        headers["Authorization"] = "Basic " + base64_auth_str

    read = "can_read"
    edit = "can_edit"
    create = "can_create"
    delete = "can_delete"
    menu = "menu_access"

    # add general permissions
    permissions = []
    read_permissions = make_permissions(read,["Task Instances", "Website", "DAG Runs", "Audit Logs", "ImportError", "XComs", \
        "DAG Code", "Plugins", "My Password", "My Profile", "Jobs", "SLA Misses", "DAG Dependencies", "Task Logs"])
    edit_permissions = make_permissions(edit, ["Task Instances", "My Password", "My Profile", "DAG Runs"])
    create_permissions = make_permissions(create, ["DAG Runs", "Task Instances"])
    delete_permissions = make_permissions(delete, ["DAG Runs", "Task Instances"])
    menu_permissions = make_permissions(menu, ["View Menus", "Browse", "Docs", "Documentation", "SLA Misses", "Jobs", "DAG Runs", \
        "Audit Logs", "Task Instances", "DAG Dependencies"])
    permissions += read_permissions + edit_permissions + create_permissions + delete_permissions + menu_permissions

    # add dag-specific permissions
    for dag in dag_names:
        dag = "DAG:" + dag
        read_permissions = make_permissions(read,[dag])
        edit_permissions = make_permissions(edit, [dag])
        delete_permissions = make_permissions(delete, [dag])
        permissions += read_permissions + edit_permissions + delete_permissions
    
    data = {
        "actions": [
            *permissions
        ],
        "name": new_role_name
    }

    airflow_url += "/api/v1/roles"
    response = requests.post(airflow_url, json=data, headers=headers)

    if response.status_code == 403:
        raise PermissionError(f"Error 403 returned, please check if your AirFlow account is Op/Admin or verify the dags exist. \n {response.json()}")
    elif response.status_code == 401:
        raise PermissionError(f"Error 401 returned, please check the access token if the page is protected by an authentication")
    elif response.status_code == 200:
        print(f"Role `{new_role_name}` successfully created.")
        return
    elif response.status_code == 409:  # Role already exists, update it
        print("Role already exists, updating...")
        airflow_role_update_url = f"{airflow_url}/{new_role_name}"
        update_response = requests.patch(airflow_role_update_url, json=data, headers=headers)
        if update_response.status_code == 200:
            print(f"Role `{new_role_name}` successfully updated.")
        else:
            raise ConnectionError(f"An error occurred during role update: {update_response.json()}")
    else:
        raise ConnectionError(f"An error occurred during role creation: {response.json()}")

def make_permissions(action, resources):
    permissions = []
    for perm in resources:
        permissions.append(make_permission(action, perm))
    return permissions

def make_permission(action, resource):
    return {
        "action": {"name": action},
        "resource": {"name": resource}
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--airflow-url", required=True, help="URL to the composer Airflow UI root page")
    parser.add_argument("-r", "--role-name", required=True, help="Name of the new created role")
    parser.add_argument("-d", "--dags", nargs="+", required=True, help="List of accessible dags for the role")
    parser.add_argument("-t", "--access-token", required=False, help="Google access token used only if Airflow is managed by Cloud Composer")
    parser.add_argument("-afu", "--airflow-username", required=False, help="Airflow username for Basic Auth")
    parser.add_argument("-afp", "--airflow-password", required=False, help="Airflow password for Basic Auth")

    args = parser.parse_args()
    create_rbac_role_with_permissions(
        airflow_url=args.airflow_url,
        new_role_name=args.role_name,
        dag_names=args.dags,
        google_access_token=args.access_token,
        airflow_username=args.airflow_username,
        airflow_password=args.airflow_password
    )
