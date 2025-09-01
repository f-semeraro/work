# Vulnerability Viewer

Client-side tool to visualize Grype JSON reports. Load an SPDX JSON file and inspect vulnerabilities in a sortable, paginated table. Filters allow narrowing by severity, fix status and risk metrics, and rows are grouped by CVE using the DataTables RowGroup extension.

## Usage
1. Open `index.html` in a modern browser.
2. Click the file chooser and select a JSON report produced by Grype (`grype -o json`). The file must contain `spdxVersion` and a `matches` array.
3. Adjust the filters for severity, fix status, EPSS, percentile, risk score or search a specific CVE ID.
4. Click a CVE group header to expand or collapse its matching rows.

The results counter shows total matches along with the number of unique CVEs and artifacts affected.
