$(document).ready(function () {
  const columnCount = 8;
  let collapsedGroups = {};

  const table = $("#cveTable").DataTable({
    data: [],
    columns: [
      {
        title: "CVE ID",
        data: "id",
        render: data => `<a href="https://nvd.nist.gov/vuln/detail/${data}" target="_blank">${data}</a>`
      },
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
      emptyDataGroup: "Unknown",
      startRender: function (rows, group) {
        const collapsed = !!collapsedGroups[group];
        rows.nodes().each(r => {
          if (collapsed) $(r).hide();
          else $(r).show();
        });
        let text = group || "Unknown";
        const count = rows.count();
        if (count > 1) text += ` (${count})`;
        return $("<tr/>")
          .append(`<td colspan="${columnCount}">${text}</td>`)
          .attr("data-name", group)
          .toggleClass("collapsed", collapsed);
      }
    },
    pageLength: 50
  });

  table.rowGroup().disable();
  let storedOrder = table.order();

  function loadData(json) {
    const rows = json.matches.map(item => ({
      id: item.vulnerability.id,
      severity: item.vulnerability.severity,
      namespace: item.vulnerability.namespace,
      epss: item.vulnerability.epss?.[0]?.epss ?? "n/a",
      percentile: item.vulnerability.epss?.[0]?.percentile ?? "n/a",
      risk: item.vulnerability.risk ?? "n/a",
      fix: item.vulnerability.fix?.state || "unknown",
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
    collapsedGroups = {};
    const val = $(this).val();
    if (val) {
      if (!table.rowGroup().enabled()) {
        storedOrder = table.order();
      }
      const colIndex = val === "id" ? 0 : 7;
      table.rowGroup().dataSrc(val).enable();
      table.order([colIndex, "asc"]).draw();
    } else {
      table.rowGroup().disable();
      table.order(storedOrder).draw();
    }
  });

  $("#cveTable tbody").on("click", "tr.dtrg-start", function () {
    const name = $(this).data("name");
    collapsedGroups[name] = !collapsedGroups[name];
    table.draw(false);
  });

  $("#severityFilter").on("change", function () {
    table.column(1).search(this.value).draw();
  });

  $("#fixFilter").on("change", function () {
    table.column(6).search(this.value).draw();
  });
});
