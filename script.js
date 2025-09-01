let cveData = [];
let filteredData = [];
let currentPage = 1;
let resultsPerPage = 50;

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
  currentPage = 1;
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

document.getElementById("collapseAll").addEventListener("click", () => {
  document.querySelectorAll("#cve-list details").forEach(d => d.open = false);
});

document.getElementById("expandAll").addEventListener("click", () => {
  document.querySelectorAll("#cve-list details").forEach(d => d.open = true);
});



function applyFilters() {
  currentPage = 1;
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
  resultsPerPage = parseInt(document.getElementById("perPage").value);
  const uniqueCves = new Set(filteredData.map(f => f.vulnerability.id));
  const uniqueArtifacts = new Set(filteredData.map(f => f.artifact?.id));

  if (filteredData.length === 0) {
    document.getElementById("cve-list").innerHTML = "<div class=\"no-results\">No results found.</div>";
    document.getElementById("resultsCount").textContent = "No results";
    const pagination = document.getElementById("pagination");
    pagination.innerHTML = "";
    pagination.style.display = "none";
    return;
  }

  // Using <details> for an accessible, keyboard-friendly disclosure of groups
  const grouped = filteredData.reduce((acc, item) => {
    const id = item.vulnerability.id;
    (acc[id] = acc[id] || []).push(item);
    return acc;
  }, {});

  const groups = Object.entries(grouped);
  const totalPages = Math.ceil(groups.length / resultsPerPage);
  if (currentPage > totalPages && totalPages > 0) {
    currentPage = 1;
  }

  const start = (currentPage - 1) * resultsPerPage;
  const end = start + resultsPerPage;
  const currentGroups = groups.slice(start, end);

  const list = currentGroups.map(([cveId, items]) => {
    const entries = items.map(item => {
      const epss = item.vulnerability.epss?.[0]?.epss ?? "n/a";
      const artifactName = item.artifact?.id ?? "Unknown";
      const percentile = item.vulnerability.epss?.[0]?.percentile ?? "n/a";
      const percentileFormatted = typeof percentile === 'number' ? (percentile * 100).toFixed(2) + '%' : "n/a";
      const risk = item.vulnerability.risk ?? "n/a";
      const riskFormatted = typeof risk === 'number' ? risk.toFixed(2) : "n/a";
      const fixState = item.vulnerability.fix?.state ?? "unknown";
      return `
        <div class=\"cve-entry\">
          <div>Artifact: ${artifactName}</div>
          <div>Severity: ${item.vulnerability.severity}</div>
          <div>Namespace: ${item.vulnerability.namespace}</div>
          <div>EPSS: ${epss}</div>
          <div>Percentile: ${percentileFormatted}</div>
          <div>Risk Score: ${riskFormatted}</div>
          <div>Fix Status: <strong>${fixState}</strong></div>
        </div>
      `;
    }).join("");
    const count = items.length > 1 ? ` (${items.length})` : "";
    return `<details open><summary><a style=\"color: #005f73\" href=\"https://nvd.nist.gov/vuln/detail/${cveId}\" target=\"_blank\">${cveId}</a>${count}</summary>${entries}</details>`;
  }).join("");

  const container = document.getElementById("cve-list");
  container.classList.add("cve-group");
  container.innerHTML = list;
  document.getElementById("resultsCount").textContent =
    `Showing ${start + 1}-${Math.min(end, groups.length)} of ${groups.length} CVEs | Matches: ${filteredData.length} | Artifacts: ${uniqueArtifacts.size}`;

  const pagination = document.getElementById("pagination");
  pagination.style.display = "";
  pagination.innerHTML = `
    Page ${currentPage} of ${totalPages}
    <button onclick=\"changePage(-1)\" ${currentPage === 1 ? "disabled" : ""}>⬅</button>
    <button onclick=\"changePage(1)\" ${currentPage === totalPages ? "disabled" : ""}>➡</button>
  `;
}

function changePage(delta) {
  currentPage += delta;
  render();
}
