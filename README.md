# GCP Services Toolkit

This Python toolkit performs several auditing and reporting tasks on a Google Cloud Platform (GCP) project.

The toolkit currently supports the following tools (all run by default):

1.  **Firewall Rule Inspector & Cleaner Tool**
    * Lists all VPC firewall rules in the GCP project.
    * Flags rules that allow overly permissive ingress (e.g., from `0.0.0.0/0` to sensitive ports) based on configurable criteria in `config.json`.
    * If the `--delete` flag is used, it can delete flagged rules.
    * Supports a `--dry-run` mode to simulate changes without making them.

2.  **IAM Policy Scanner Tool**
    * Lists IAM policies for all Cloud Storage buckets in the GCP project.
    * Flags policies that grant highly permissive roles (e.g., `roles/storage.admin`) to public principals (`allUsers` or `allAuthenticatedUsers`), based on the `config.json` configuration file.
    * Suggests a remediation plan.

3.  **GCP BigQuery Count Reporter Tool**
    * Analyzes actual BigQuery job history for the configured GCP project and reporting region by querying its `INFORMATION_SCHEMA.JOBS_BY_PROJECT` view.
    * Aggregates the total number of queries executed and the total bytes billed by these queries on a per-day basis for a configurable period (e.g., the past 7 days, as set in `config.json`).
    * Outputs a daily summary to the log, including the number of queries and the volume of bytes billed.
    * Identifies the "busiest day" within the reported period based on the highest number of queries.

## Prerequisites

* Python 3.9 or higher (due to type hints like `str | None`). If using older Python (3.8), adjust type hints to use `Optional[str]` from `typing`.
* `gcloud` CLI installed and authenticated:
    * Run `gcloud auth application-default login` for Application Default Credentials.
* The following GCP APIs must be enabled on the target project:
    * Compute Engine API (`compute.googleapis.com`)
    * Cloud Storage API (`storage.googleapis.com`) & IAM API (`iam.googleapis.com`)
    * BigQuery API (`bigquery.googleapis.com`)
    * Service Usage API (`serviceusage.googleapis.com`)

## Setup Instructions

1.  **Project Directory:**
    Ensure all project files (`main.py`, `tools.py`, `config.sample.json`, `requirements.txt`) are in a single root directory.

2.  **Virtual Environment (Recommended):**
    ```bash
    python -m venv venv
    ```
    Activate:
    * Linux/macOS: `source venv/bin/activate`
    * Windows: `venv\Scripts\activate`

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure the Tool:**
    * Copy `config.sample.json` to `config.json`:
        ```bash
        cp config.sample.json config.json # Linux/macOS
        # copy config.sample.json config.json # Windows
        ```
    * **Edit `config.json`**: Crucially, set your `project_id`. Review and adjust other settings for each tool's section as needed.

## Running the Tool
All commands are run from the project's root directory with the virtual environment activated. The script will execute all registered tools by default.

**Command Line Interface:**
```bash
python main.py --config ./config.json [--delete] [--dry-run]
