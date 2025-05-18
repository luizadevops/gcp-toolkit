# GCP Cloud Engineer Challenge Tool

This Python tool is a submission for the GCP Cloud Engineer coding challenge. It performs several auditing and reporting tasks on a Google Cloud Platform (GCP) project, broken down into three main cases:

1.  **Firewall Rule Inspector & Cleaner**
    * Lists all VPC firewall rules in a GCP project.
    * Flags rules that allow overly permissive ingress (e.g., from `0.0.0.0/0` to sensitive ports) based on a configurable definition.
    * Optionally deletes flagged rules (with `--delete` flag, supports `--dry-run`).

2.  **IAM Policy Scanner**
    * Lists IAM policies for all Cloud Storage buckets in the GCP project.
    * Flags policies granting `roles/storage.admin` to `allUsers` or `allAuthenticatedUsers`.
    * Suggests a remediation plan for flagged policies.

3.  **GCP Query Count Reporter**
    * Runs a predefined set of sample queries against BigQuery public datasets multiple times.
    * Logs each query execution timestamp to a local file.
    * Aggregates these query counts per day for the past 7 days.
    * Outputs a summary identifying the total queries per day and the busiest day.

The tool is designed to be modular, configurable via a JSON file, and provides clear logging output.

## Prerequisites

* Python 3.8 or higher.
* `gcloud` CLI installed and authenticated:
    * Run `gcloud auth application-default login` to set up Application Default Credentials.
* The following GCP APIs must be enabled on the target project:
    * Compute Engine API (`compute.googleapis.com`)
    * Cloud Storage API (`storage.googleapis.com`)
    * BigQuery API (`bigquery.googleapis.com`)
    * IAM API (`iam.googleapis.com`)
    * Service Usage API (`serviceusage.googleapis.com`) - (for enabling other APIs or if the script needs to check)

## Setup Instructions

1.  **Clone the Repository (or Unpack Files):**
    If this project is in a Git repository, clone it. Otherwise, ensure all project files (`main.py`, `config.sample.json`, `requirements.txt`, and the package directories: `firewall_inspector/`, `iam_scanner/`, `cost_reporter/`, `gcp_utils/`) are in a single root directory.

2.  **Create and Activate a Python Virtual Environment (Recommended):**
    ```bash
    python -m venv venv
    ```
    Activate the environment:
    * Linux/macOS:
        ```bash
        source venv/bin/activate
        ```
    * Windows (Command Prompt):
        ```bash
        venv\Scripts\activate.bat
        ```
    * Windows (PowerShell):
        ```bash
        venv\Scripts\Activate.ps1
        ```

3.  **Install Dependencies:**
    With the virtual environment activated, install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure the Tool:**
    * Copy the sample configuration file:
        ```bash
        cp config.sample.json config.json
        ```
        (On Windows, use `copy config.sample.json config.json`)
    * Edit `config.json` and **set your `project_id`**. Review and adjust other settings for each case as needed (e.g., sample BigQuery queries, firewall permissive criteria, etc.).

## Running the Tool

All commands should be run from the root directory of the project, with your virtual environment activated.

**Basic Command Structure:**
```bash
python main.py --config ./config.json [options]