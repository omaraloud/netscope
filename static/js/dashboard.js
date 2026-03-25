/**
 * NetScope — Dashboard Client
 * ---------------------------
 * Connects to the Flask-SocketIO server, receives live packet events,
 * updates the DOM table, and drives three Chart.js charts.
 */

"use strict";

// ── Config ──────────────────────────────────────────────────────────────────
const MAX_TABLE_ROWS   = 200;
const PPS_HISTORY_LEN  = 60;   // seconds of packets/sec history shown on chart

// Protocol → CSS badge class
const BADGE_CLASS = {
  TCP:   "badge--tcp",
  UDP:   "badge--udp",
  ICMP:  "badge--icmp",
  DNS:   "badge--dns",
  HTTP:  "badge--http",
  Other: "badge--other",
};

// Chart.js protocol colours (order must match PROTO_ORDER)
const PROTO_ORDER  = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "Other"];
const PROTO_COLORS = [
  "rgba(56,139,253,.8)",
  "rgba(188,140,255,.8)",
  "rgba(255,166,87,.8)",
  "rgba(63,185,80,.8)",
  "rgba(247,129,102,.8)",
  "rgba(139,148,158,.8)",
];

// ── DOM refs ─────────────────────────────────────────────────────────────────
const tbody       = document.getElementById("packet-tbody");
const totalCount  = document.getElementById("total-count");
const ppsDisplay  = document.getElementById("pps-display");
const statusDot   = document.getElementById("status-dot");
const statusLabel = document.getElementById("status-label");

let packetCounter = 0;

// ── Chart.js global defaults ─────────────────────────────────────────────────
Chart.defaults.color          = "#8b949e";
Chart.defaults.borderColor    = "#30363d";
Chart.defaults.font.family    = "'SF Mono','Fira Code',Consolas,monospace";
Chart.defaults.font.size      = 11;
Chart.defaults.animation      = false;   // disable for real-time performance

// ── Protocol Distribution (doughnut) ────────────────────────────────────────
const protoChart = new Chart(
  document.getElementById("chart-protocol"),
  {
    type: "doughnut",
    data: {
      labels:   PROTO_ORDER,
      datasets: [{
        data:            PROTO_ORDER.map(() => 0),
        backgroundColor: PROTO_COLORS,
        borderWidth:     2,
        borderColor:     "#161b22",
        hoverOffset:     6,
      }],
    },
    options: {
      responsive:         true,
      maintainAspectRatio: true,
      cutout:             "65%",
      plugins: {
        legend: {
          position: "right",
          labels: { boxWidth: 10, padding: 8, color: "#8b949e" },
        },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.parsed.toLocaleString()}`,
          },
        },
      },
    },
  }
);

// ── Packets Per Second (line) ────────────────────────────────────────────────
const ppsLabels  = Array.from({ length: PPS_HISTORY_LEN }, (_, i) => "");
const ppsData    = Array(PPS_HISTORY_LEN).fill(0);

const ppsChart = new Chart(
  document.getElementById("chart-pps"),
  {
    type: "line",
    data: {
      labels:   ppsLabels,
      datasets: [{
        label:           "pkt/s",
        data:            ppsData,
        borderColor:     "#58a6ff",
        backgroundColor: "rgba(88,166,255,.08)",
        borderWidth:     2,
        fill:            true,
        tension:         0.3,
        pointRadius:     0,
      }],
    },
    options: {
      responsive:          true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
      },
      scales: {
        x: { display: false },
        y: {
          beginAtZero: true,
          grid:  { color: "rgba(48,54,61,.7)" },
          ticks: { precision: 0 },
        },
      },
    },
  }
);

// ── Top Talkers (horizontal bar) ─────────────────────────────────────────────
const talkersChart = new Chart(
  document.getElementById("chart-talkers"),
  {
    type: "bar",
    data: {
      labels:   [],
      datasets: [{
        label:           "Packets",
        data:            [],
        backgroundColor: "rgba(63,185,80,.7)",
        borderRadius:    3,
        borderWidth:     0,
      }],
    },
    options: {
      indexAxis:           "y",
      responsive:          true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
      },
      scales: {
        x: {
          beginAtZero: true,
          grid:  { color: "rgba(48,54,61,.7)" },
          ticks: { precision: 0 },
        },
        y: {
          grid: { display: false },
          ticks: { font: { size: 10 } },
        },
      },
    },
  }
);

// ── SocketIO connection ───────────────────────────────────────────────────────
const socket = io({
  reconnection:        true,
  reconnectionDelay:   1000,
  reconnectionAttempts: Infinity,
});

socket.on("connect", () => {
  setStatus("connected", "Connected");
});

socket.on("disconnect", () => {
  setStatus("connecting", "Reconnecting…");
});

socket.on("connect_error", () => {
  setStatus("error", "Connection error");
});

// ── Packet events ─────────────────────────────────────────────────────────────
socket.on("packet", (pkt) => {
  prependRow(pkt, true);
  packetCounter++;
  totalCount.textContent = packetCounter.toLocaleString();
});

// Bulk history on initial connect
socket.on("history", (packets) => {
  for (const pkt of packets) {
    prependRow(pkt, false);
    packetCounter++;
  }
  totalCount.textContent = packetCounter.toLocaleString();
});

// ── Stats events ──────────────────────────────────────────────────────────────
socket.on("stats", (stats) => {
  // Packets per second
  const pps = stats.packets_per_second ?? 0;
  ppsDisplay.textContent = pps;
  ppsData.push(pps);
  ppsData.shift();
  ppsChart.update("none");

  // Protocol distribution
  const counts = stats.protocol_counts ?? {};
  protoChart.data.datasets[0].data = PROTO_ORDER.map((p) => counts[p] ?? 0);
  protoChart.update("none");

  // Top talkers
  const talkers = stats.top_talkers ?? [];
  talkersChart.data.labels                 = talkers.map((t) => t.ip);
  talkersChart.data.datasets[0].data       = talkers.map((t) => t.count);
  talkersChart.update("none");
});

// ── Table helpers ─────────────────────────────────────────────────────────────
function prependRow(pkt, animate) {
  const tr = document.createElement("tr");
  if (animate) tr.classList.add("new-row");

  // Time (show only HH:MM:SS.mmm)
  const timeStr = pkt.timestamp
    ? pkt.timestamp.split("T")[1] ?? pkt.timestamp
    : "";

  tr.innerHTML = `
    <td title="${esc(pkt.timestamp)}">${esc(timeStr)}</td>
    <td title="${esc(pkt.src_ip)}">${esc(pkt.src_ip)}</td>
    <td title="${esc(pkt.dst_ip)}">${esc(pkt.dst_ip)}</td>
    <td><span class="badge ${badgeClass(pkt.protocol)}">${esc(pkt.protocol)}</span></td>
    <td>${pkt.length ?? ""}</td>
    <td title="${esc(pkt.info)}">${esc(pkt.info)}</td>
  `;

  tbody.insertBefore(tr, tbody.firstChild);

  // Trim table to rolling window size
  while (tbody.rows.length > MAX_TABLE_ROWS) {
    tbody.deleteRow(tbody.rows.length - 1);
  }
}

function badgeClass(proto) {
  return BADGE_CLASS[proto] ?? "badge--other";
}

function esc(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── Status indicator ──────────────────────────────────────────────────────────
function setStatus(state, label) {
  statusDot.className   = `status-dot status-dot--${state}`;
  statusLabel.textContent = label;
}
