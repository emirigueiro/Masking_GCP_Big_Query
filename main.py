from google.cloud import storage, bigquery, datacatalog_v1
from google.api_core.exceptions import NotFound
from google.iam.v1 import policy_pb2
from datetime import datetime
import pandas as pd
import io
import flask
import base64
import time

# -------------------------------------------------------------------------------------------------------------------
# Parámetros globales
PROJECT_ID = "test-1-426619"         #Completar: ID del proyecto.
LOCATION = "us"                      #Completar: Zona de ubicación del proyecto.
BUCKET_NAME = "archivos_rls"        #Completar: Nombre del bucket de Cloud Storage.
SHEET_PATH = "masking_policies.csv"  #Completar: Nombre del archivo CSV.
BQ_DATASET = "test_RLS"              #Completar: Dataset en donde se alocara la tabla de auditoria.
BQ_TABLE = "masking_reglas"          #Completar: Nombre de la tabla que contendra las reglas de Masking en Bigquery.
BQ_AUDIT_TABLE = "masking_auditoria" #Completar: Nombre de la tabla de auditoría en BigQuery.


# -------------------------------------------------------------------------------------------------------------------
# Creacion/actualizacion de la tabla que contiene las reglas de Masking en BigQuery     
def extract_sheet_from_gcs():
    client = storage.Client()
    bucket = client.bucket(BUCKET_NAME.replace("gs://", ""))
    blob = bucket.blob(SHEET_PATH)
    content = blob.download_as_text()
    df = pd.read_csv(io.StringIO(content))
    print(f"Archivo leído correctamente. Filas: {len(df)}")
    df.to_csv("/tmp/masking_policies.csv", index=False)

def load_config_to_bq():
    client = bigquery.Client(project=PROJECT_ID)
    table_ref = f"{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}"

    auditoria = []
    batch_id = 1
    try:
        result = client.query(f"SELECT COALESCE(MAX(batch_id), 0) AS max_batch FROM `{table_ref}`").to_dataframe()
        batch_id = int(result["max_batch"].iloc[0]) + 1
    except Exception:
        pass

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

# -------------------------------------------------------------------------------------------------------------------
# Eliminacion de las reglas de Masking pre existentes  
def clear_existing_policies():
    bq_client = bigquery.Client(project=PROJECT_ID)
    datacatalog_client = datacatalog_v1.PolicyTagManagerClient()

    print("🧹 Eliminando Policy Tags previos...")
    tables = list(bq_client.list_tables(f"{PROJECT_ID}.{BQ_DATASET}"))
    for table_item in tables:
        table_ref = f"{PROJECT_ID}.{BQ_DATASET}.{table_item.table_id}"
        table = bq_client.get_table(table_ref)
        new_schema = []
        modified = False

        for field in table.schema:
            if getattr(field, "policy_tags", None) and field.policy_tags.names:
                print(f"Removiendo policy tag de {field.name} en {table_ref}")
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

    print("🧹 Eliminando taxonomías anteriores...")
    parent = f"projects/{PROJECT_ID}/locations/{LOCATION}"
    for taxonomy in datacatalog_client.list_taxonomies(parent=parent):
        try:
            datacatalog_client.delete_taxonomy(name=taxonomy.name)
            print(f"Taxonomía eliminada: {taxonomy.display_name}")
        except Exception as e:
            print(f"No se pudo eliminar {taxonomy.display_name}: {e}")

# -------------------------------------------------------------------------------------------------------------------
# Generacion dinamica y aplicacion de las reglas de Masking. Creacion/actualizacion de la tabla de auditoria 
def apply_masking_from_config():
    bq_client = bigquery.Client(project=PROJECT_ID)
    datacatalog_client = datacatalog_v1.PolicyTagManagerClient()
    audit_table_ref = f"{PROJECT_ID}.{BQ_DATASET}.{BQ_AUDIT_TABLE}"

    auditoria = []
    batch_id = 1
    try:
        result = bq_client.query(f"SELECT COALESCE(MAX(batch_id), 0) AS max_batch FROM `{audit_table_ref}`").to_dataframe()
        batch_id = int(result["max_batch"].iloc[0]) + 1
    except Exception:
        pass

    # Crear tabla de auditoría si no existe
    try:
        bq_client.get_table(audit_table_ref)
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
            bigquery.SchemaField("batch_id", "INTEGER"),
        ]
        bq_client.create_table(bigquery.Table(audit_table_ref, schema=schema))

    # Leer configuraciones de masking
    query = f"SELECT project_id, dataset_id, table_id, column_name, restricted_users FROM `{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}`"
    rows = bq_client.query(query).result()

    # Obtener o crear taxonomía
    parent = f"projects/{PROJECT_ID}/locations/{LOCATION}"
    taxonomy_name = None
    for taxonomy in datacatalog_client.list_taxonomies(parent=parent):
        if taxonomy.display_name == "Masking":
            taxonomy_name = taxonomy.name
            break

    if not taxonomy_name:
        taxonomy = datacatalog_v1.Taxonomy(
            display_name="Masking",
            activated_policy_types=[datacatalog_v1.Taxonomy.PolicyType.FINE_GRAINED_ACCESS_CONTROL],
        )
        taxonomy = datacatalog_client.create_taxonomy(parent=parent, taxonomy=taxonomy)
        taxonomy_name = taxonomy.name

    # Preparar auditoría
    auditoria = []

    for row in rows:
        project_id, dataset_id, table_id, column_name = row.project_id, row.dataset_id, row.table_id, row.column_name
        restricted_users = [u.strip() for u in row.restricted_users.split(",")]
        policy_tag_display_name = f"{table_id}_{column_name}_mask"

        # Crear o recuperar policy tag
        existing_tags = list(datacatalog_client.list_policy_tags(parent=taxonomy_name))
        existing = next((t for t in existing_tags if t.display_name == policy_tag_display_name), None)
        if existing:
            policy_tag_name = existing.name
        else:
            policy_tag_obj = datacatalog_client.create_policy_tag(
                parent=taxonomy_name,
                policy_tag=datacatalog_v1.PolicyTag(
                    display_name=policy_tag_display_name,
                    description=f"Oculta columna {column_name} en {table_id}",
                ),
            )
            policy_tag_name = policy_tag_obj.name

        # Actualizar schema de BigQuery
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

        #  Completa los campos de la tabla de Auditoria
        auditoria.append({
            "timestamp": datetime.utcnow().isoformat(),
            "taxonomy_name": taxonomy_name,
            "policy_tag_name": policy_tag_name,
            "project_id": project_id,
            "dataset_id": dataset_id,
            "table_id": table_id,
            "column_name": column_name,
            "restricted_users": ",".join(restricted_users),
            "batch_id": batch_id
        })

    # Insertar auditoría en batch
    bq_client.insert_rows_json(audit_table_ref, auditoria)

# ---------------------------------------------------------------------
# Cloud Function principal
def main(request):
    try:
        extract_sheet_from_gcs()
        load_config_to_bq()
        clear_existing_policies()
        apply_masking_from_config()
        print("Proceso completado correctamente")
        return ("Proceso de Masking completado", 200)
    except Exception as e:
        print(f"Error: {e}")
        return (str(e), 500)
