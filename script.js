$(document).ready(function () {
  const columnCount = 8;
  let collapsedGroups = {};

    let severitySelect, fixSelect;

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
          const icon = collapsed ? "&#9654;" : "&#9660;";
          return $("<tr/>")
            .append(`<td colspan="${columnCount}">${icon} ${text}</td>`)
            .attr("data-name", group)
            .toggleClass("collapsed", collapsed);
        }
      },
      pageLength: 50,
      initComplete: function () {
        const api = this.api();
        api.columns([1, 6]).every(function () {
          const column = this;
          const label = column.index() === 1 ? 'Severity' : 'Fix Status';
          const select = $('<select><option value=""></option></select>')
            .appendTo($(column.header()).empty())
            .on('change', function () {
              const val = $.fn.dataTable.util.escapeRegex($(this).val());
              column.search(val ? '^' + val + '$' : '', true, false).draw();
            });
          $(column.header()).prepend(label + '<br>');
          if (column.index() === 1) severitySelect = select; else fixSelect = select;
        });
      }
    });

  table.rowGroup().disable();
  let storedOrder = table.order();

    function updateFilters() {
      [
        { select: severitySelect, column: 1 },
        { select: fixSelect, column: 6 }
      ].forEach(function (item) {
        item.select.find('option:not(:first)').remove();
        table.column(item.column).data().unique().sort().each(function (d) {
          item.select.append(`<option value="${d}">${d}</option>`);
        });
      });
    }

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
      updateFilters();
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
        $("#collapseAll, #expandAll").prop("disabled", false);
      } else {
        table.rowGroup().disable();
        table.order(storedOrder).draw();
        $("#collapseAll, #expandAll").prop("disabled", true);
      }
    });

    $("#cveTable tbody").on("click", "tr.dtrg-start", function () {
      const name = $(this).data("name");
      collapsedGroups[name] = !collapsedGroups[name];
      table.draw(false);
    });

    $("#collapseAll").on("click", function () {
      if (!table.rowGroup().enabled()) return;
      const src = table.rowGroup().dataSrc();
      const colIndex = src === "id" ? 0 : 7;
      collapsedGroups = {};
      table.column(colIndex, { search: 'applied' }).data().unique().each(function (d) {
        collapsedGroups[d] = true;
      });
      table.draw(false);
    });

    $("#expandAll").on("click", function () {
      if (!table.rowGroup().enabled()) return;
      collapsedGroups = {};
      table.draw(false);
    });
});
