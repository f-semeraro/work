$(document).ready(function () {
  const table = $("#cveTable").DataTable({
    data: [],
    columns: [
      { title: "CVE ID", data: "id" },
      { title: "Severity", data: "severity" },
      { title: "Namespace", data: "namespace" },
      { title: "EPSS", data: "epss" },
      { title: "Percentile", data: "percentile" },
      { title: "Risk Score", data: "risk" },
      { title: "Fix Status", data: "fix" },
      { title: "Artifact", data: "artifact" }
    ],
    rowGroup: {
      dataSrc: "artifact",
      emptyDataGroup: "Unknown"
    },
    pageLength: 50
  });

  table.rowGroup().disable();

  function loadData(json) {
    const rows = json.matches.map(item => ({
      id: item.vulnerability.id,
      severity: item.vulnerability.severity,
      namespace: item.vulnerability.namespace,
      epss: item.vulnerability.epss?.[0]?.epss ?? "n/a",
      percentile: item.vulnerability.epss?.[0]?.percentile ?? "n/a",
      risk: item.vulnerability.risk ?? "n/a",
      fix: item.vulnerability.fix?.state ?? "unknown",
      artifact: item.artifact?.id ?? "Unknown"
    }));
    table.clear();
    table.rows.add(rows).draw();
  }

  fetch("test.json")
    .then(r => r.json())
    .then(data => loadData(data))
    .catch(err => console.error("Failed to load test.json", err));

  $("#fileInput").on("change", function (event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const json = JSON.parse(e.target.result);
        loadData(json);
      } catch (err) {
        alert("ERROR parsing JSON file");
      }
    };
    reader.readAsText(file);
  });

  $("#groupBy").on("change", function () {
    const val = $(this).val();
    if (val) {
      table.rowGroup().dataSrc(val).enable().draw();
    } else {
      table.rowGroup().disable().draw();
    }
  });
});

