# ---------------------------------------------------------------------------------------------------------------------------------
# Dependencias:

from airflow import DAG
from airflow.operators.python import PythonOperator
from datetime import datetime
from google.cloud import storage, bigquery, datacatalog_v1
from google.api_core.exceptions import NotFound, AlreadyExists
import pandas as pd
import io
from google.iam.v1 import policy_pb2

# ---------------------------------------------------------------------------------------------------------------------------------
# Parámetros de ejecución:

PROJECT_ID = "integra-bbdd-adduntia"             #Completar: ID del proyecto en donde se aloja el Dataset con la tabla de reglas de Masking.
LOCATION = "us"                                  #Completar: Zona en la que se encuentra alocado el proyecto. 
BUCKET_NAME = "us-central1-test-96d39955-bucket" #Completar: Nombre del bucket de Google Cloud Storage.
SHEET_PATH = "data/masking_policies.csv"         #Completar: Carpeta y nombre del archivo con las reglas de Masking.
BQ_DATASET = "Data_Adduntia_Sheets"              #Completar: Dataset en donde se alojara la tabla con las reglas de Masking.
BQ_TABLE = "masking_policies"                    #Completar: Nombre de la tabla que contendra las reglas de Masking.
BQ_AUDIT_TABLE = "masking_auditoria"             #Completar: Nombre de la tabla de auditoría que registrara las implementaciones de Masking.

# ---------------------------------------------------------------------------------------------------------------------------------
# Descargar el sheet desde GCS:

def extract_sheet_from_gcs(**kwargs):
    client = storage.Client()
    bucket = client.bucket(BUCKET_NAME.replace("gs://", ""))
    blob = bucket.blob(SHEET_PATH)
    content = blob.download_as_text()
    df = pd.read_csv(io.StringIO(content))
    print(f"Archivo leído correctamente. Filas: {len(df)}")
    df.to_csv("/tmp/masking_policies.csv", index=False)

# ---------------------------------------------------------------------------------------------------------------------------------
# Cargar el archivo en BigQuery:

def load_config_to_bq(**kwargs):
    client = bigquery.Client(project=PROJECT_ID)
    table_ref = f"{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}"

    job_config = bigquery.LoadJobConfig(
        source_format=bigquery.SourceFormat.CSV,
        skip_leading_rows=1,
        write_disposition="WRITE_TRUNCATE",
        schema=[
            bigquery.SchemaField("project_id", "STRING"),
            bigquery.SchemaField("dataset_id", "STRING"),
            bigquery.SchemaField("table_id", "STRING"),
            bigquery.SchemaField("column_name", "STRING"),
            bigquery.SchemaField("restricted_users", "STRING"),
        ],
    )

    with open("/tmp/masking_policies.csv", "rb") as f:
        job = client.load_table_from_file(f, table_ref, job_config=job_config)
        job.result()

    print(f"Configuración cargada exitosamente en {table_ref}")

# ---------------------------------------------------------------------------------------------------------------------------------
# Eliminar taxonomías/policy tags anteriores:

def clear_existing_policies(**kwargs):
    bq_client = bigquery.Client(project=PROJECT_ID)
    datacatalog_client = datacatalog_v1.PolicyTagManagerClient()

    print("Eliminando Policy Tags de las tablas existentes...")
    tables = list(bq_client.list_tables(f"{PROJECT_ID}.{BQ_DATASET}"))
    for table_item in tables:
        table_ref = f"{PROJECT_ID}.{BQ_DATASET}.{table_item.table_id}"
        table = bq_client.get_table(table_ref)
        new_schema = []
        modified = False

        for field in table.schema:
            if getattr(field, "policy_tags", None) and field.policy_tags.names:
                print(f"Quitando policy tag de columna: {field.name} en {table_ref}")
                clean_field = bigquery.SchemaField(
                    name=field.name,
                    field_type=field.field_type,
                    mode=field.mode,
                    description=field.description,
                    fields=field.fields,
                )
                new_schema.append(clean_field)
                modified = True
            else:
                new_schema.append(field)

        if modified:
            table.schema = new_schema
            bq_client.update_table(table, ["schema"])
            print(f"Policy tags eliminados en {table_ref}")

    print("Eliminando taxonomías anteriores...")
    parent = f"projects/{PROJECT_ID}/locations/{LOCATION}"
    for taxonomy in datacatalog_client.list_taxonomies(parent=parent):
        try:
            datacatalog_client.delete_taxonomy(name=taxonomy.name)
            print(f"Taxonomía eliminada: {taxonomy.display_name}")
        except Exception as e:
            print(f"No se pudo eliminar {taxonomy.display_name}: {e}")


# ---------------------------------------------------------------------------------------------------------------------------------
# Aplicar políticas y registrar auditoría:

def apply_masking_from_config(**kwargs):
    bq_client = bigquery.Client(project=PROJECT_ID)
    datacatalog_client = datacatalog_v1.PolicyTagManagerClient()

    # Crear tabla de auditoría si no existe
    audit_table_ref = f"{PROJECT_ID}.{BQ_DATASET}.{BQ_AUDIT_TABLE}"
    try:
        bq_client.get_table(audit_table_ref)
        print(f"Tabla de auditoría existente: {audit_table_ref}")
    except NotFound:
        schema = [
            bigquery.SchemaField("timestamp", "TIMESTAMP"),
            bigquery.SchemaField("taxonomy_name", "STRING"),
            bigquery.SchemaField("policy_tag_name", "STRING"),
            bigquery.SchemaField("project_id", "STRING"),
            bigquery.SchemaField("dataset_id", "STRING"),
            bigquery.SchemaField("table_id", "STRING"),
            bigquery.SchemaField("column_name", "STRING"),
            bigquery.SchemaField("restricted_users", "STRING"),
        ]
        table = bigquery.Table(audit_table_ref, schema=schema)
        bq_client.create_table(table)
        print(f"Tabla de auditoría creada: {audit_table_ref}")

    # Leer configuraciones de la tabla masking_policies
    query = f"""
    SELECT project_id, dataset_id, table_id, column_name, restricted_users
    FROM `{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}`
    """
    rows = bq_client.query(query).result()

    parent = f"projects/{PROJECT_ID}/locations/{LOCATION}"

    # Reutilizar o crear taxonomía
    taxonomy_name = None
    for taxonomy in datacatalog_client.list_taxonomies(parent=parent):
        if taxonomy.display_name == "Masking":
            taxonomy_name = taxonomy.name
            print(f"Taxonomía 'Masking' existente reutilizada: {taxonomy_name}")
            break

    if not taxonomy_name:
        taxonomy = datacatalog_v1.Taxonomy(
            display_name="Masking",
            activated_policy_types=[datacatalog_v1.Taxonomy.PolicyType.FINE_GRAINED_ACCESS_CONTROL],
        )
        taxonomy = datacatalog_client.create_taxonomy(parent=parent, taxonomy=taxonomy)
        taxonomy_name = taxonomy.name
        print(f"Creada nueva taxonomía: {taxonomy_name}")

    # Aplicar políticas
    for row in rows:
        project_id, dataset_id, table_id, column_name = row.project_id, row.dataset_id, row.table_id, row.column_name
        restricted_users = [u.strip() for u in row.restricted_users.split(",")]
        policy_tag_display_name = f"{table_id}_{column_name}_mask"

        # Crear o reutilizar policy tag
        existing_tags = list(datacatalog_client.list_policy_tags(parent=taxonomy_name))
        existing = next((t for t in existing_tags if t.display_name == policy_tag_display_name), None)
        if existing:
            policy_tag_name = existing.name
            print(f"Policy Tag existente reutilizado: {policy_tag_name}")
        else:
            policy_tag = datacatalog_v1.PolicyTag(
                display_name=policy_tag_display_name,
                description=f"Oculta columna {column_name} en {table_id}",
            )
            policy_tag_obj = datacatalog_client.create_policy_tag(parent=taxonomy_name, policy_tag=policy_tag)
            policy_tag_name = policy_tag_obj.name
            print(f"Policy Tag creado: {policy_tag_name}")

        # Aplicar en tabla
        table_ref = f"{project_id}.{dataset_id}.{table_id}"
        table = bq_client.get_table(table_ref)
        new_schema = []
        for field in table.schema:
            if field.name == column_name:
                field = bigquery.SchemaField(
                    field.name, field.field_type, mode=field.mode,
                    policy_tags=bigquery.PolicyTagList(names=[policy_tag_name]),
                )
            new_schema.append(field)
        table.schema = new_schema
        bq_client.update_table(table, ["schema"])
        print(f"Policy Tag aplicado en {table_ref}.{column_name}")

        # Revocar acceso
        policy = datacatalog_client.get_iam_policy(request={"resource": policy_tag_name})
        new_policy = policy_pb2.Policy()
        for binding in policy.bindings:
            allowed_members = [m for m in binding.members if m not in [f"user:{u}" for u in restricted_users]]
            if allowed_members:
                new_binding = new_policy.bindings.add()
                new_binding.role = binding.role
                new_binding.members.extend(allowed_members)
        datacatalog_client.set_iam_policy(request={"resource": policy_tag_name, "policy": new_policy})
        print(f"Acceso restringido a {restricted_users}")

        # Registrar auditoría
        audit_row = [{
            "timestamp": datetime.utcnow().isoformat(),
            "taxonomy_name": taxonomy_name,
            "policy_tag_name": policy_tag_name,
            "project_id": project_id,
            "dataset_id": dataset_id,
            "table_id": table_id,
            "column_name": column_name,
            "restricted_users": ",".join(restricted_users),
        }]
        errors = bq_client.insert_rows_json(audit_table_ref, audit_row)
        if errors:
            print(f"Error al insertar auditoría: {errors}")
        else:
            print(f"Auditoría registrada para {table_id}.{column_name}")

    print("Aplicación de políticas y auditoría completadas.")

# ---------------------------------------------------------------------------------------------------------------------------------
# DAG:

with DAG(
    dag_id="Politicas_Masking",
    start_date=datetime(2025, 1, 1),
    schedule_interval=None,
    catchup=False,
    default_args={"retries": 0},
    tags=["datacatalog", "masking", "bq", "automation"],
) as dag:

    Lectura_Sheet = PythonOperator(task_id="Lectura_Sheet", python_callable=extract_sheet_from_gcs)
    Sheet_a_GCP = PythonOperator(task_id="Sheet_a_GCP", python_callable=load_config_to_bq)
    Limpieza_politicas_existentes = PythonOperator(task_id="Limpieza_politicas_existentes", python_callable=clear_existing_policies)
    Aplica_masking = PythonOperator(task_id="Aplica_masking", python_callable=apply_masking_from_config)

    Lectura_Sheet >> Sheet_a_GCP >> Limpieza_politicas_existentes >> Aplica_masking
