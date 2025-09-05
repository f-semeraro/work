$(document).ready(function () {
  // --- Constants and shared state ---
  const COLUMN_COUNT = 8;                // number of columns in the table
  const HEADER_OFFSET = $("#controls").outerHeight();

  let collapsedGroups = {};              // track which row groups are collapsed
  let storedOrder = [];                  // previous sorting before grouping

  // --- DataTables initialisation ---
  const table = new DataTable('#cveTable', {
    fixedHeader: {
      header: true,
      headerOffset: HEADER_OFFSET
    },
    data: [],
    columns: [
      {
        title: "CVE ID",
        data: "id",
        // link to the NIST CVE details page
        render: data =>
          `<a href="https://nvd.nist.gov/vuln/detail/${data}" target="_blank">${data}</a>`
      },
      { title: "Severity", data: "severity" },
      { title: "Namespace", data: "namespace" },
      { title: "EPSS", data: "epss" },
      { title: "Percentile", data: "percentile" },
      { title: "Risk Score", data: "risk" },
      { title: "Fix Status", data: "fix" },
      { title: "Artifact", data: "artifact" }
    ],
    columnControl: [
      {
            target: 0,
            content: ['order','colVisDropdown','reorder']
      },
      { target: 1, content: ['search'] },
      
    ],
    ordering: {
        indicators: false,
        handler: false
    },
    rowGroup: {
      dataSrc: "artifact",
      emptyDataGroup: "Unknown",
      // custom rendering of the group header allowing collapse/expand
      startRender: function (rows, group) {
        const collapsed = !!collapsedGroups[group];

        // hide or show the rows depending on collapse state
        rows.nodes().each(r => {
          collapsed ? $(r).hide() : $(r).show();
        });

        // group label with item count and arrow icon
        let text = group || "Unknown";
        const count = rows.count();
        if (count > 1) text += ` (${count})`;
        const icon = collapsed ? "&#9654;" : "&#9660;";

        return $("<tr/>")
          .append(`<td colspan="${COLUMN_COUNT}">${icon} ${text}</td>`)
          .attr("data-name", group)
          .toggleClass("collapsed", collapsed);
      }
    },
      pageLength: 50,
      columnDefs: [
        { targets: [3, 4, 5], type: 'num' }
      ],
      layout: {
        top1: {
            buttons: ['copy', 'csv', 'excel', 'pdf', 'print']
        },
        topStart: ['searchPanes'],
        bottomStart: ['info'],
        bottomEnd: ['pageLength', 'paging']
      },
      searchPanes: {
        columns: [1, 6]
      },
      initComplete: function () {
        const dtFooter = $('#dtFooter');
        dtFooter.append($('#cveTable_info'));
        dtFooter.append($('#cveTable_length'));
        dtFooter.append($('#cveTable_paginate'));
        $('#cveTable_wrapper .dt-layout-row:last').css('display', 'none');
      }
    });

  table.rowGroup().disable();

  // --- Helpers ---------------------------------------------------------

  // Load JSON data into the table and refresh search panes
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
    table.searchPanes.clearSelections();
    table.searchPanes.rebuildPane();
    table.fixedHeader.adjust();
  }

  // --- Initial data load ----------------------------------------------

  fetch("test.json")
    .then(r => r.json())
    .then(data => loadData(data))
    .catch(err => console.error("Failed to load test.json", err));

  // --- Event bindings --------------------------------------------------

  // Allow user to load a custom JSON file
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

  // Handle grouping selector
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

  // Toggle a single group when its header is clicked
  $("#cveTable tbody").on("click", "tr.dtrg-start", function () {
    const name = $(this).data("name");
    collapsedGroups[name] = !collapsedGroups[name];
    table.draw(false);
  });

  // Collapse all groups
  $("#collapseAll").on("click", function () {
    if (!table.rowGroup().enabled()) return;
    const src = table.rowGroup().dataSrc();
    const colIndex = src === "id" ? 0 : 7;

    collapsedGroups = {};
    table
      .column(colIndex, { search: "applied" })
      .data()
      .unique()
      .each(function (d) {
        collapsedGroups[d] = true;
      });
    table.draw(false);
  });

  // Expand all groups
  $("#expandAll").on("click", function () {
    if (!table.rowGroup().enabled()) return;
    collapsedGroups = {};
    table.draw(false);
  });
});
