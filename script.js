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
      currentPage = 1;
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

document.getElementById("searchId").addEventListener("input", () => {
  currentPage = 1;
  applyFilters();
});

document.getElementById("riskThreshold").addEventListener("input", () => {
  currentPage = 1;
  applyFilters();
});

document.querySelectorAll('input[name="severity"]').forEach(cb => {
  cb.addEventListener("change", () => {
    currentPage = 1;
    applyFilters();
  });
});

document.querySelectorAll('input[name="fixstate"]').forEach(cb => {
  cb.addEventListener("change", () => {
    currentPage = 1;
    applyFilters();
  });
});

document.getElementById("percentileThreshold").addEventListener("input", () => {
  currentPage = 1;
  applyFilters();
});

document.getElementById("riskScore").addEventListener("input", () => {
  currentPage = 1;
  applyFilters();
});



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
  resultsPerPage = parseInt(document.getElementById("perPage").value);

  if (filteredData.length === 0) {
    document.getElementById("cve-list").innerHTML = "<div class=\"no-results\">No results found.</div>";
    document.getElementById("resultsCount").textContent = "No results";
    const pagination = document.getElementById("pagination");
    pagination.innerHTML = "";
    pagination.style.display = "none";
    return;
  }

  const totalPages = Math.ceil(filteredData.length / resultsPerPage);
  if (currentPage > totalPages && totalPages > 0) {
    currentPage = 1;
  }

  const start = (currentPage - 1) * resultsPerPage;
  const end = start + resultsPerPage;
  const currentItems = filteredData.slice(start, end);

  const list = currentItems.map(item => {
    const epss = item.vulnerability.epss?.[0]?.epss ?? "n/a";
    const artifactName = item.artifact?.id ?? "Unknown";
    const percentile = item.vulnerability.epss?.[0]?.percentile ?? "n/a";
  const percentileFormatted = typeof percentile === 'number' ? (percentile * 100).toFixed(2) + '%' : "n/a";
  const risk = item.vulnerability.risk ?? "n/a";
  const riskFormatted = typeof risk === 'number' ? risk.toFixed(2) : "n/a";
    const fixState = item.vulnerability.fix?.state ?? "unknown";
    return `
      <div class="cve-entry">
        <strong><a style="color: #005f73" href="https://nvd.nist.gov/vuln/detail/${item.vulnerability.id}" target="_blank">
          ${item.vulnerability.id}
        </a></strong>
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

  document.getElementById("cve-list").innerHTML = list;

  document.getElementById("resultsCount").textContent =
  `Showing ${start + 1}-${Math.min(end, filteredData.length)} of ${filteredData.length} results`;

  const pagination = document.getElementById("pagination");
  pagination.style.display = "";
  pagination.innerHTML = `
    Page ${currentPage} of ${totalPages}
    <button onclick="changePage(-1)" ${currentPage === 1 ? "disabled" : ""}>⬅</button>
    <button onclick="changePage(1)" ${currentPage === totalPages ? "disabled" : ""}>➡</button>
  `;
}

function changePage(delta) {
  currentPage += delta;
  render();
}
