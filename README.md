
# 🛡️ Masking_GCP_BigQuery

In this repository, you can find a simple way to manage **Masking policies** in **GCP BigQuery** directly from a Google Sheet (in CSV format).  

---

## 🧠 Project Description

The main idea of this project is to define **masking policies** in a Google Sheet, allowing them to be applied in **BigQuery** quickly and easily.  
The process reads the policies defined in the Sheet (previously uploaded to a **Cloud Storage bucket**), builds the **masking rules** (taxonomies and policy tags), and applies them to the specified **tables and users**.

---

## ⚙️ Process Overview

1. 📥 Download a CSV file with the policy configuration from a **GCS bucket**.  
2. 🗃️ Load this configuration into a **BigQuery table**.  
3. 🧹 Clean all previous policies (policy tags and taxonomies).  
4. 🧩 Create new **taxonomies**, **policy tags**, and apply the **masking rules** to users, projects, datasets, tables, and columns.  

> ⚠️ **Note:**  
> In the project folder, you will find an example Sheet (masking_policies_sheet.csv) to test the process.  
> The Sheet **must be in CSV format** and stored inside a **GCP Bucket** so that the **Cloud Function** or **Airflow DAG** can locate and execute it.  
> Both the **DAG** and **Cloud Function** must be triggered manually.

---

## 🔁 Sequential Flow

Lectura_Sheet → Sheet_a_GCP → Limpieza_politicas_existentes → Aplica_masking


---

## 📄 Step 1: Extract CSV from GCS

**Function:** `extract_sheet_from_gcs`  
**Objective:** Download the CSV file containing the masking rules.

**Steps:**
- Connects to the bucket defined in `BUCKET_NAME` using `google.cloud.storage`.
- Downloads the file defined in `SHEET_PATH` (e.g., `data/masking_policies.csv`).
- Loads the content into a **pandas DataFrame**.
- Temporarily saves the CSV in `/tmp/masking_policies.csv`.

**Result:**  
A local CSV available with the following columns:
  project_id,
  dataset_id,
  table_id,
  column_name,
  restricted_users


---

## 📊 Step 2: Load CSV into BigQuery

**Function:** `load_config_to_bq`  
**Objective:** Load the CSV configuration into a **BigQuery table** for easier management and version control.

**Steps:**
- Connects to BigQuery using `bigquery.Client`.
- Defines the table name: `{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}`.
- Configures `LoadJobConfig` for CSV format.
- Ignores the first row (headers).
- Replaces previous content (`WRITE_TRUNCATE`).
- Defines the column schema.
- Loads the CSV from `/tmp/filename.csv`.

**Result:**  
The table `masking_policies` in BigQuery now contains the masking rules to apply.

---

## 🧹 Step 3: Clean Existing Policies

**Function:** `clear_existing_policies`  
**Objective:** Remove existing taxonomies, policy tags, and column-level masking to avoid duplication and maintain a clean environment.

**Steps:**
**a. Clean columns in BigQuery:**
- List all tables in the dataset (`bq_client.list_tables`).
- Iterate through columns and remove any associated `policy_tag`.
- Update the table (`bq_client.update_table`).

**b. Delete existing taxonomies:**
- List all taxonomies in the project (`list_taxonomies`).
- Delete them using `delete_taxonomy`.

**Result:**  
All tables are left without previous masking, and no taxonomies remain active.

---

## 🔒 Step 4: Create and Apply New Policies

**Function:** `apply_masking_from_config`  
**Objective:** Create and apply new masking policies defined in the `masking_policies` BigQuery table.

**Steps:**

```sql
SELECT
  project_id,
  dataset_id,
  table_id,
  column_name,
  restricted_users
FROM `PROJECT.DATASET.masking_policies`
```

## 📄 Process sumary: 

🏷️ Create New Taxonomy
Uses datacatalog_v1.PolicyTagManagerClient().create_taxonomy().
Taxonomy name: "Masking".
Enables Fine-Grained Access Control.
Acts as the main container for access policies.

🔖 Create Policy Tag
Creates a tag named {table_id}_{column_name}_mask.
Adds a description (e.g., “Hides country column in sales table”).
Each masked column has its own tag.

🧱 Apply Policy Tag to Column
Retrieves the table (bq_client.get_table).
Iterates through columns and adds the corresponding policy_tag.
Updates the schema (bq_client.update_table).

🚫 Revoke Access for Restricted Users
Retrieves the IAM policy (get_iam_policy).
Builds a new policy (policy_pb2.Policy).
Excludes users listed in restricted_users.
Applies it with set_iam_policy.

Result:
Users defined as restricted can no longer see the masked column content.

🧩 Technologies Used

☁️ Google Cloud Platform (GCP)
BigQuery
Data Catalog
Cloud Storage
Cloud Functions / Airflow (Composer)
🐍 Python
pandas


🧪 Example Sheet
project_id	dataset_id	table_id	column_name	restricted_users
my_project	sales_data	orders	    customer_id	user1@test.com


📬 Contact
Created by Emiliano Rigueiro
💼 Data Engineer | GCP | Python | BigQuery