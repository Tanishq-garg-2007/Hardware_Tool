import React, { useState } from "react";

export default function NewAnalyzeBootLog() {
  const [file, setFile] = useState(null);
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
      setError(""); // clear any previous errors
    }
  };

  const handleAnalyze = async () => {
    if (!file) {
      setError("Please select a bootlog file first.");
      return;
    }

    setError("");
    setLoading(true);
    setResults([]); // clear previous results

    try {
      const formData = new FormData();
      
      // CRITICAL CHANGE: We must use "upload_file" to match the FastAPI backend parameter:
      // async def cves_endpoint(upload_file: UploadFile = File(...)):
      formData.append("upload_file", file);

      // Send the API request
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/new_cves`, {
        method: "POST",
        body: formData, // Browser automatically sets headers for multipart/form-data
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Failed to fetch data from backend");
      }

      // Update state with the backend payload
      setResults(data.vulnerabilities || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <h2 style={styles.heading}>Bootlog CVE Risk Analyzer</h2>

      {/* FILE INPUT */}
      <input
        type="file"
        accept=".txt,.log"
        onChange={handleFileChange}
        style={styles.fileInput}
      />

      {/* BUTTON */}
      <button 
        type="button" 
        onClick={handleAnalyze} 
        style={styles.button}
        disabled={loading}
      >
        {loading ? "Analyzing Bootlog... (This may take a minute)" : "Upload & Analyze"}
      </button>

      {/* ERROR MESSAGE */}
      {error && <p style={styles.error}>{error}</p>}

      {/* RESULTS TABLE */}
      {results.length > 0 && (
        <div style={styles.tableContainer}>
          <table style={styles.table}>
            <thead>
              <tr style={styles.tableRow}>
                <th style={styles.tableHeader}>CVE ID</th>
                <th style={styles.tableHeader}>CVSS Base Score</th>
                <th style={styles.tableHeader}>EPSS Score</th>
                <th style={styles.tableHeader}>EPSS Percentile</th>
              </tr>
            </thead>
            <tbody>
              {results.map((item, index) => (
                <tr key={index} style={styles.tableRow}>
                  {/* These keys now perfectly match your Python backend output */}
                  <td style={styles.tableCell}>{item.id || "-"}</td>
                  <td style={styles.tableCell}>{item.baseScore || "-"}</td>
                  <td style={styles.tableCell}>{item.epssScore || "-"}</td>
                  <td style={styles.tableCell}>{item.epssPercentile || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const styles = {
  container: {
    maxWidth: "900px",
    margin: "40px auto",
    padding: "20px",
    textAlign: "center",
    border: "1px solid #ddd",
    borderRadius: "12px",
    backgroundColor: "#fafafa",
    fontFamily: "sans-serif",
  },
  heading: {
    marginBottom: "20px",
  },
  fileInput: {
    display: "block",
    margin: "0 auto 20px auto",
    padding: "10px",
    border: "1px dashed #ccc",
    borderRadius: "6px",
    backgroundColor: "#fff",
    cursor: "pointer",
  },
  button: {
    padding: "10px 20px",
    fontSize: "16px",
    cursor: "pointer",
    borderRadius: "6px",
    border: "none",
    backgroundColor: "#007bff",
    color: "#fff",
  },
  error: {
    color: "red",
    marginTop: "10px",
    fontWeight: "bold",
  },
  tableContainer: {
    marginTop: "25px",
    overflowX: "auto",
  },
  table: {
    width: "100%",
    borderCollapse: "collapse",
    backgroundColor: "#fff",
  },
  tableRow: {
    borderBottom: "1px solid #eee",
  },
  tableHeader: {
    padding: "12px",
    backgroundColor: "#f4f4f4",
    fontWeight: "bold",
    textAlign: "left",
  },
  tableCell: {
    padding: "12px",
    textAlign: "left",
  },
};
