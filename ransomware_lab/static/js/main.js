// main.js
$(document).ready(function() {
  $('#logTable').DataTable({
    pageLength: 10,
    lengthMenu: [5, 10, 25, 50],
    columns: [
      { width: "4%" }, // ID
      { width: "12%" }, // Time
      { width: "22%" }, // Filename
      { width: "14%" }, // Process
      { width: "12%" }, // Action
      { width: "8%" },  // Status
      { width: "20%" }, // Details
      { width: "8%" }   // Quarantined
    ],
    order: [[0, "desc"]],
    language: {
      emptyTable: "No logs yet (try submitting an event)"
    }
  });
});
