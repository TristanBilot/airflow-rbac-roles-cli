# airflow-rbac-roles-cli
Airflow provides a way to manage permissions: RBAC. However, this system is only available from UI. Many use cases such as the implementation of an Airflow orchestrator for multiple projects need to take profit of dag-level permissions in order to only authorize some users to access specific project dags. **Creating roles with dag-level permissions on multiple dags directly from the UI is very error-prone and time-consuming.**

That's why I created a script which given the **airflow url**, the **dag names** and the **new role name**, will automatically create the role with the needed permissions to access only these dags and not the other dags deployed on Airflow. 

> The tool can be used to create roles for multiple projects inside a same Airflow.

## Usage
```shell
python3 rbac_roles_cli.py -u airflow_url -r new_role_name -d dag1 dag2
```
Will create a role named `new_role_name` on the airflow project at the url `airflow_url` with enough permissions to only manage the dags `dag1` and `dag2`. 

Note that the permissions can be edited directly in the code and following the syntax used in the <a href="https://github.com/apache/airflow/blob/d1f3d8ec19d3c3b2494fbcd5a1adb5be4d4af03b/airflow/security/permissions.py"> Airflow code</a>.

## Compatibility with Cloud Composer
GCP offers Cloud Composer: a Google-managed Airflow. The script also work with Composer, you only need to add an argument to the command: <a href="https://www.daimto.com/how-to-get-a-google-access-token-with-curl/"> the Google access-token</a>. This token is used in order to access the Composer page which is protected by a Google authentication page.

```shell
python3 rbac_roles_cli.py -u airflow_url -r new_role_name -d dag1 dag2 -t access_token
```
