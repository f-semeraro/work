let cveData = [];
let filteredData = [];
let groupByCve = false;
let collapsedGroups = {};

document.getElementById("fileInput").addEventListener("change", (event) => {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      cveData = JSON.parse(e.target.result).matches;
      applyFilters();
    } catch (err) {
      alert("ERROR parsing JSON file");
    }
  };
  reader.readAsText(file);
});

document.getElementById("perPage").addEventListener("change", () => {
  render();
});

document.getElementById("groupToggle").addEventListener("change", (e) => {
  groupByCve = e.target.checked;
  render();
});

document.getElementById("searchId").addEventListener("input", applyFilters);

document.getElementById("riskThreshold").addEventListener("input", applyFilters);

document.querySelectorAll('input[name="severity"]').forEach(cb => {
  cb.addEventListener("change", applyFilters);
});

document.querySelectorAll('input[name="fixstate"]').forEach(cb => {
  cb.addEventListener("change", applyFilters);
});

document.getElementById("percentileThreshold").addEventListener("input", applyFilters);

document.getElementById("riskScore").addEventListener("input", applyFilters);

function applyFilters() {
  const selectedSeverities = Array.from(document.querySelectorAll('input[name="severity"]:checked')).map(cb => cb.value);
  const selectedFixStates = Array.from(document.querySelectorAll('input[name="fixstate"]:checked')).map(cb => cb.value);
  const searchId = document.getElementById("searchId").value.toLowerCase();
  const epssThreshold = parseFloat(document.getElementById("riskThreshold").value) || 0;
  const percentileThreshold = parseFloat(document.getElementById("percentileThreshold").value) || 0;
  const riskScoreThreshold = parseFloat(document.getElementById("riskScore").value) || 0;

  filteredData = cveData.filter(item => {
    const idMatch = item.vulnerability.id.toLowerCase().includes(searchId);
    const severityMatch = selectedSeverities.length === 0 || selectedSeverities.includes(item.vulnerability.severity);
    const epss = item.vulnerability.epss?.[0]?.epss || 0;
    const percentile = item.vulnerability.epss?.[0]?.percentile || 0;
    const risk = item.vulnerability.risk || 0;
    const riskMatch = epss >= epssThreshold && percentile >= percentileThreshold && risk >= riskScoreThreshold;
    const fixState = item.vulnerability.fix?.state ?? "unknown";
    const fixStateMatch = selectedFixStates.length === 0 || selectedFixStates.includes(fixState);

    return idMatch && severityMatch && riskMatch && fixStateMatch;
  });

  render();
}


function render() {
  const resultsPerPage = parseInt(document.getElementById("perPage").value);
  const uniqueCves = new Set(filteredData.map(f => f.vulnerability.id));
  const uniqueArtifacts = new Set(filteredData.map(f => f.artifact?.id));

  const tableBody = document.querySelector("#cveTable tbody");
  tableBody.innerHTML = "";

  if (filteredData.length === 0) {
    if ($.fn.dataTable.isDataTable('#cveTable')) {
      $('#cveTable').DataTable().clear().destroy();
    }
    document.getElementById("resultsCount").textContent = "No results";
    return;
  }

  filteredData.forEach(item => {
    const row = document.createElement('tr');

    const cveCell = document.createElement('td');
    const link = document.createElement('a');
    link.href = `https://nvd.nist.gov/vuln/detail/${item.vulnerability.id}`;
    link.textContent = item.vulnerability.id;
    link.target = "_blank";
    cveCell.appendChild(link);
    row.appendChild(cveCell);

    const artifactCell = document.createElement('td');
    artifactCell.textContent = item.artifact?.id ?? 'Unknown';
    row.appendChild(artifactCell);

    const severityCell = document.createElement('td');
    severityCell.textContent = item.vulnerability.severity;
    row.appendChild(severityCell);

    const namespaceCell = document.createElement('td');
    namespaceCell.textContent = item.vulnerability.namespace;
    row.appendChild(namespaceCell);

    const epssCell = document.createElement('td');
    epssCell.textContent = item.vulnerability.epss?.[0]?.epss ?? 'n/a';
    row.appendChild(epssCell);

    const percentileCell = document.createElement('td');
    const percentile = item.vulnerability.epss?.[0]?.percentile;
    percentileCell.textContent = typeof percentile === 'number' ? (percentile * 100).toFixed(2) + '%' : 'n/a';
    row.appendChild(percentileCell);

    const riskCell = document.createElement('td');
    const risk = item.vulnerability.risk;
    riskCell.textContent = typeof risk === 'number' ? risk.toFixed(2) : 'n/a';
    row.appendChild(riskCell);

    const fixCell = document.createElement('td');
    fixCell.textContent = item.vulnerability.fix?.state ?? 'unknown';
    row.appendChild(fixCell);

    tableBody.appendChild(row);
  });

  if ($.fn.dataTable.isDataTable('#cveTable')) {
    $('#cveTable').DataTable().clear().destroy();
  }

  collapsedGroups = {};

  const config = {
    pageLength: resultsPerPage,
    lengthChange: false,
    order: [[0, 'asc']]
  };

  if (groupByCve) {
    config.rowGroup = {
      dataSrc: 0,
      startRender: function(rows, group) {
        const collapsed = !!collapsedGroups[group];
        rows.nodes().each(r => {
          r.style.display = collapsed ? 'none' : '';
        });
        return $('<tr/>')
          .append(`<td colspan="8">${group} (${rows.count()})</td>`)
          .attr('data-name', group)
          .toggleClass('collapsed', collapsed);
      }
    };
  }

  const table = $('#cveTable').DataTable(config);

  if (groupByCve) {
    $('#cveTable tbody').off('click', 'tr.dtrg-start').on('click', 'tr.dtrg-start', function () {
      const name = $(this).data('name');
      collapsedGroups[name] = !collapsedGroups[name];
      table.draw(false);
    });
  }

  document.getElementById("resultsCount").textContent =
    `Matches: ${filteredData.length} | CVEs: ${uniqueCves.size} | Artifacts: ${uniqueArtifacts.size}`;
}
