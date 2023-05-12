# python3 rbac_roles_cli.py -user <USER_NAME> -pass <PASSWORD> -u http://<IP>:<PORT> -r NEW_ROLE -d DAG_NAME_1 DAG_NAME_2

from typing import List
import requests
import argparse
from requests.auth import HTTPBasicAuth

def create_rbac_role_with_permissions(
    airflow_url: str,
    new_role_name: str,
    dag_names: List[str]
):
    
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

    return data


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


def on_login(airflow_user_api, airflow_pass_api, airflow_url, data, new_role_name):

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    
    try:
    
      credentials=HTTPBasicAuth(airflow_user_api, airflow_pass_api)
      
      airflow_url += "/api/v1/roles"
      response = requests.post(airflow_url, json=data, headers=headers, auth=credentials, timeout=5)
          
      if response.status_code == 403:
        raise RuntimeError(f"Error 403 returned, please check if your AirFlow account is Op/Admin or verify the dags exist. \n {response.json()}")
      elif response.status_code == 401:
        raise RuntimeError(f"Error 401 returned, please check the access token if the page is protected by an authentication")
      elif response.status_code == 200:
        print(f"Role `{new_role_name}` successfuly created.")
      else:
        raise RuntimeError(f"An error occured during role creation: {response.json()}")
        
    except requests.exceptions.HTTPError as errh:
      raise RuntimeError('A HTTPError error occurred') from errh
    except requests.exceptions.ConnectionError as errc:
      raise RuntimeError('A Connection error occurred') from errc
    except requests.exceptions.Timeout as errt:
      raise RuntimeError('A Timeout error occurred') from errt
    except requests.exceptions.RequestException as err:
      raise RuntimeError('A Request Exception error occurred') from err

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-user", "--airflow-user-api", required=True, help="User access to the Airflow UI root page")
    parser.add_argument("-pass", "--airflow-pass-api", required=True, help="Password access to the composer Airflow UI root page")
    parser.add_argument("-u", "--airflow-url", required=True, help="URL to the composer Airflow UI root page")
    parser.add_argument("-r", "--role-name", required=True, help="Name of the new created role")
    parser.add_argument("-d", "--dags", nargs="+", required=True, help="List of accessible dags for the role")

    args = parser.parse_args()
    
    try:
    
     data = create_rbac_role_with_permissions(
          args.airflow_url,
          args.role_name,
          args.dags,
      )

      on_login(args.airflow_user_api, args.airflow_pass_api, args.airflow_url, data, args.role_name)
     
    except RuntimeError as errh:
      print("It didn't work:", errh)
      if errh.__cause__:
        print('Cause:', errh.__cause__)
