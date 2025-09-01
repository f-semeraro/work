let cveData = [];
let filteredData = [];
let collapsedGroups = {};

// File loading
const fileInput = document.getElementById('fileInput');
fileInput.addEventListener('change', (event) => {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const json = JSON.parse(e.target.result);
      cveData = Array.isArray(json.matches) ? json.matches : [];
      applyFilters();
    } catch (err) {
      alert('ERROR parsing JSON file');
    }
  };
  reader.readAsText(file);
});

// Filters
const perPage = document.getElementById('perPage');
perPage.addEventListener('change', render);

document.getElementById('searchId').addEventListener('input', applyFilters);
document.getElementById('riskThreshold').addEventListener('input', applyFilters);
document.getElementById('percentileThreshold').addEventListener('input', applyFilters);
document.getElementById('riskScore').addEventListener('input', applyFilters);

document.querySelectorAll('input[name="severity"]').forEach(cb => cb.addEventListener('change', applyFilters));
document.querySelectorAll('input[name="fixstate"]').forEach(cb => cb.addEventListener('change', applyFilters));

function applyFilters() {
  const selectedSeverities = Array.from(document.querySelectorAll('input[name="severity"]:checked')).map(cb => cb.value);
  const selectedFixStates = Array.from(document.querySelectorAll('input[name="fixstate"]:checked')).map(cb => cb.value);
  const searchId = document.getElementById('searchId').value.toLowerCase();
  const epssThreshold = parseFloat(document.getElementById('riskThreshold').value) || 0;
  const percentileThreshold = parseFloat(document.getElementById('percentileThreshold').value) || 0;
  const riskScoreThreshold = parseFloat(document.getElementById('riskScore').value) || 0;

  filteredData = cveData.filter(item => {
    const idMatch = item.vulnerability.id.toLowerCase().includes(searchId);
    const severityMatch = selectedSeverities.length === 0 || selectedSeverities.includes(item.vulnerability.severity);
    const epss = item.vulnerability.epss?.[0]?.epss || 0;
    const percentile = item.vulnerability.epss?.[0]?.percentile || 0;
    const risk = item.vulnerability.risk || 0;
    const riskMatch = epss >= epssThreshold && percentile >= percentileThreshold && risk >= riskScoreThreshold;
    const fixState = item.vulnerability.fix?.state ?? 'unknown';
    const fixStateMatch = selectedFixStates.length === 0 || selectedFixStates.includes(fixState);
    return idMatch && severityMatch && riskMatch && fixStateMatch;
  });

  render();
}

function render() {
  const resultsPerPage = parseInt(perPage.value);
  const uniqueCves = new Set(filteredData.map(f => f.vulnerability.id));
  const uniqueArtifacts = new Set(filteredData.map(f => f.artifact?.id));

  if ($.fn.dataTable.isDataTable('#cveTable')) {
    $('#cveTable').DataTable().clear().destroy();
  }

  if (filteredData.length === 0) {
    $('#cveTable tbody').empty();
    document.getElementById('resultsCount').textContent = 'No results';
    return;
  }

  const dataSet = filteredData.map(item => ({
    cve: item.vulnerability.id,
    artifact: item.artifact?.id ?? 'Unknown',
    severity: item.vulnerability.severity,
    namespace: item.vulnerability.namespace,
    epss: item.vulnerability.epss?.[0]?.epss ?? 'n/a',
    percentile: item.vulnerability.epss?.[0]?.percentile,
    risk: item.vulnerability.risk,
    fix: item.vulnerability.fix?.state ?? 'unknown'
  }));

  collapsedGroups = {};

  const table = $('#cveTable').DataTable({
    data: dataSet,
    columns: [
      { data: 'cve', render: data => `<a href="https://nvd.nist.gov/vuln/detail/${data}" target="_blank">${data}</a>` },
      { data: 'artifact' },
      { data: 'severity' },
      { data: 'namespace' },
      { data: 'epss' },
      { data: 'percentile', render: data => typeof data === 'number' ? (data * 100).toFixed(2) + '%' : 'n/a' },
      { data: 'risk', render: data => typeof data === 'number' ? data.toFixed(2) : 'n/a' },
      { data: 'fix' }
    ],
    pageLength: resultsPerPage,
    lengthChange: false,
    order: [[0, 'asc']],
    rowGroup: {
      dataSrc: 'cve',
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
    }
  });

  $('#cveTable tbody').off('click', 'tr.dtrg-start').on('click', 'tr.dtrg-start', function() {
    const name = $(this).data('name');
    collapsedGroups[name] = !collapsedGroups[name];
    table.draw(false);
  });

  document.getElementById('resultsCount').textContent =
    `Matches: ${filteredData.length} | CVEs: ${uniqueCves.size} | Artifacts: ${uniqueArtifacts.size}`;
}
