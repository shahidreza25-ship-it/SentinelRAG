document.addEventListener("DOMContentLoaded", () => {

    // ============================================================
    // ELEMENTS
    // ============================================================

    const analyzeButton = document.getElementById("analyzeBtn");
    const valueInput = document.getElementById("iocValue");
    const typeInput = document.getElementById("iocType");

    const reportButton =
        document.getElementById("downloadReportBtn") ||
        document.getElementById("reportBtn") ||
        document.getElementById("downloadReport");

    const generateReportButton =
        document.getElementById("generateReportBtn");


    // ============================================================
    // SAFETY CHECK
    // ============================================================

    if (!analyzeButton) {
        console.log("Analyze button not found.");
        return;
    }


    // ============================================================
    // ANALYZE IOC
    // ============================================================

    analyzeButton.addEventListener("click", async () => {

        const value = valueInput
            ? valueInput.value.trim()
            : "";

        if (!value) {
            alert("Please enter an IP address.");
            return;
        }

        analyzeButton.disabled = true;

        const originalText =
            analyzeButton.textContent;

        analyzeButton.textContent =
            "Analyzing...";


        try {

            // ====================================================
            // API REQUEST
            // ====================================================

            const response = await fetch(
                "/api/analyze",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        type: "IP",
                        value: value
                    })
                }
            );


            // ====================================================
            // READ RESPONSE
            // ====================================================

            const result =
                await response.json();

            console.log(
                "SENTINELRAG API RESPONSE:",
                result
            );


            // ====================================================
            // ERROR HANDLING
            // ====================================================

            if (!response.ok) {

                throw new Error(
                    result.error ||
                    `Server error: ${response.status}`
                );
            }


            // ====================================================
            // DISPLAY RESULT
            // ====================================================

            displayAnalysisResult(result);


            // ====================================================
            // SHOW RESULT SECTIONS
            // ====================================================

            showElement("analysisResult");
            showElement("resultSection");
            showElement("threatResult");


            // ====================================================
            // ENABLE REPORT
            // ====================================================

            enableReportButton(result);

        }


        catch (error) {

            console.error(
                "ANALYSIS ERROR:",
                error
            );

            alert(
                "Analysis failed: " +
                error.message
            );

        }


        finally {

            analyzeButton.disabled = false;

            analyzeButton.textContent =
                originalText;
        }

    });


    // ============================================================
    // DISPLAY ANALYSIS RESULT
    // ============================================================

    function displayAnalysisResult(result) {

        // --------------------------------------------------------
        // BASIC
        // --------------------------------------------------------

        setText(
            "indicator",
            result.indicator || "Unknown"
        );

        setText(
            "ipAddress",
            result.indicator || "Unknown"
        );

        setText(
            "ipVersion",
            result.ip_version || "Unknown"
        );

        setText(
            "ipType",
            result.ip_type || "Unknown"
        );

        setText(
            "networkType",
            result.ip_type || "Unknown"
        );

        setText(
            "purpose",
            result.purpose || "Unknown"
        );


        // --------------------------------------------------------
        // RISK
        // --------------------------------------------------------

        setText(
            "classification",
            result.classification || "UNKNOWN"
        );

        setText(
            "riskScore",
            result.risk_score ?? 0
        );

        setText(
            "confidence",
            result.confidence ?? 0
        );

        setText(
            "severity",
            result.severity || "UNKNOWN"
        );

        setText(
            "evidence",
            result.evidence ?? 0
        );


        // --------------------------------------------------------
        // LOCATION
        // --------------------------------------------------------

        setText(
            "country",
            result.country || "N/A"
        );

        setText(
            "countryCode",
            result.country_code || "N/A"
        );

        setText(
            "region",
            result.region || "N/A"
        );

        setText(
            "city",
            result.city || "N/A"
        );

        setText(
            "latitude",
            result.latitude ?? "N/A"
        );

        setText(
            "longitude",
            result.longitude ?? "N/A"
        );


        // --------------------------------------------------------
        // NETWORK
        // --------------------------------------------------------

        setText(
            "isp",
            result.isp || "N/A"
        );

        setText(
            "organization",
            result.organization || "N/A"
        );

        setText(
            "asn",
            result.asn || "N/A"
        );

        setText(
            "usageType",
            result.usage_type || "N/A"
        );


        // --------------------------------------------------------
        // THREAT INTELLIGENCE
        // --------------------------------------------------------

        setText(
            "totalReports",
            result.total_reports ?? 0
        );

        setText(
            "abuseConfidence",
            result.abuse_confidence ?? 0
        );

        setText(
            "lastReported",
            result.last_reported_at || "N/A"
        );

        setText(
            "domain",
            result.domain || "N/A"
        );


        // --------------------------------------------------------
        // DESCRIPTION
        // --------------------------------------------------------

        setText(
            "description",
            result.description ||
            "No description available."
        );


        // --------------------------------------------------------
        // SOURCE
        // --------------------------------------------------------

        setText(
            "source",
            result.source || "Unknown"
        );

        setText(
            "status",
            result.status || "Collected"
        );


        // --------------------------------------------------------
        // MITRE
        // --------------------------------------------------------

        const mitreElement =
            document.getElementById("mitre");

        if (mitreElement) {

            if (
                Array.isArray(result.mitre) &&
                result.mitre.length > 0
            ) {

                mitreElement.textContent =
                    result.mitre.join(", ");

            } else {

                mitreElement.textContent =
                    "None identified";
            }
        }


        // --------------------------------------------------------
        // HOSTNAME
        // --------------------------------------------------------

        const hostnameElement =
            document.getElementById("hostname");

        if (hostnameElement) {

            if (
                Array.isArray(result.hostname) &&
                result.hostname.length > 0
            ) {

                hostnameElement.textContent =
                    result.hostname.join(", ");

            } else {

                hostnameElement.textContent =
                    "N/A";
            }
        }


        // --------------------------------------------------------
        // RISK BAR
        // --------------------------------------------------------

        updateRiskBar(
            result.risk_score ?? 0
        );


        // --------------------------------------------------------
        // SEVERITY STYLE
        // --------------------------------------------------------

        updateSeverityStyle(
            result.severity
        );


        // --------------------------------------------------------
        // CLASSIFICATION STYLE
        // --------------------------------------------------------

        updateClassificationStyle(
            result.classification
        );


        // --------------------------------------------------------
        // STORE COMPLETE RESULT
        // --------------------------------------------------------

        window.latestAnalysis =
            result;

    }


    // ============================================================
    // ENABLE REPORT BUTTON
    // ============================================================

    function enableReportButton(result) {

        const button =
            document.getElementById("downloadReportBtn") ||
            document.getElementById("reportBtn") ||
            document.getElementById("downloadReport") ||
            document.getElementById("generateReportBtn");

        if (!button) {

            console.warn(
                "Report button not found."
            );

            return;
        }


        button.disabled = false;

        button.style.pointerEvents =
            "auto";

        button.style.opacity =
            "1";

        button.classList.remove(
            "disabled"
        );


        // Store latest report data
        button.dataset.report =
            JSON.stringify(result);


        console.log(
            "Report button enabled."
        );
    }


    // ============================================================
    // SET TEXT
    // ============================================================

    function setText(id, value) {

        const element =
            document.getElementById(id);

        if (!element) {
            return;
        }

        element.textContent =
            value;
    }


    // ============================================================
    // SHOW ELEMENT
    // ============================================================

    function showElement(id) {

        const element =
            document.getElementById(id);

        if (!element) {
            return;
        }

        element.style.display = "";

        element.classList.add(
            "visible"
        );
    }


    // ============================================================
    // RISK BAR
    // ============================================================

    function updateRiskBar(score) {

        const numericScore =
            Math.max(
                0,
                Math.min(
                    100,
                    Number(score) || 0
                )
            );


        const bar =
            document.getElementById(
                "riskBar"
            );

        const riskProgress =
            document.getElementById(
                "riskProgress"
            );


        if (bar) {

            bar.style.width =
                numericScore + "%";
        }


        if (riskProgress) {

            riskProgress.style.width =
                numericScore + "%";
        }
    }


    // ============================================================
    // SEVERITY STYLE
    // ============================================================

    function updateSeverityStyle(severity) {

        const element =
            document.getElementById(
                "severity"
            );

        if (!element) {
            return;
        }


        element.classList.remove(
            "high",
            "medium",
            "low",
            "unknown"
        );


        const value =
            String(
                severity || "UNKNOWN"
            ).toLowerCase();


        if (
            value.includes("high")
        ) {

            element.classList.add(
                "high"
            );

        } else if (
            value.includes("medium")
        ) {

            element.classList.add(
                "medium"
            );

        } else if (
            value.includes("low")
        ) {

            element.classList.add(
                "low"
            );

        } else {

            element.classList.add(
                "unknown"
            );
        }
    }


    // ============================================================
    // CLASSIFICATION STYLE
    // ============================================================

    function updateClassificationStyle(
        classification
    ) {

        const element =
            document.getElementById(
                "classification"
            );

        if (!element) {
            return;
        }


        element.classList.remove(
            "high-risk",
            "medium-risk",
            "low-risk",
            "private",
            "loopback",
            "unknown"
        );


        const value =
            String(
                classification || ""
            ).toLowerCase();


        if (
            value.includes("high")
        ) {

            element.classList.add(
                "high-risk"
            );

        } else if (
            value.includes("medium")
        ) {

            element.classList.add(
                "medium-risk"
            );

        } else if (
            value.includes("low")
        ) {

            element.classList.add(
                "low-risk"
            );

        } else if (
            value.includes("private")
        ) {

            element.classList.add(
                "private"
            );

        } else if (
            value.includes("loopback")
        ) {

            element.classList.add(
                "loopback"
            );

        } else {

            element.classList.add(
                "unknown"
            );
        }
    }


    // ============================================================
    // REPORT DOWNLOAD
    // ============================================================

    async function downloadReport() {

        if (!window.latestAnalysis) {

            alert(
                "Please analyze an IP address first."
            );

            return;
        }


        try {

            const buttons = [
                reportButton,
                generateReportButton
            ];


            buttons.forEach(
                (button) => {

                    if (button) {

                        button.disabled =
                            true;

                        button.textContent =
                            "Generating...";
                    }
                }
            );


            // ====================================================
            // SEND ANALYZED IP TO BACKEND
            // ====================================================

            const ip =
                window.latestAnalysis.indicator ||
                window.latestAnalysis.ip ||
                "";


            const response =
                await fetch(
                    "/report/download",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            ip: ip,
                            analysis:
                                window.latestAnalysis
                        })
                    }
                );


            // ====================================================
            // RESPONSE CHECK
            // ====================================================

            if (!response.ok) {

                let errorMessage =
                    "Report generation failed.";

                try {

                    const errorData =
                        await response.json();

                    errorMessage =
                        errorData.error ||
                        errorMessage;

                } catch (_) {}


                throw new Error(
                    errorMessage
                );
            }


            // ====================================================
            // DOWNLOAD FILE
            // ====================================================

            const blob =
                await response.blob();


            const url =
                window.URL.createObjectURL(
                    blob
                );


            const link =
                document.createElement(
                    "a"
                );


            link.href = url;


            const safeIP =
                ip
                    .replace(
                        /[:\/]/g,
                        "_"
                    );


            link.download =
                "SentinelRAG_Threat_Report_" +
                (safeIP || "IP") +
                ".pdf";


            document.body.appendChild(
                link
            );


            link.click();


            link.remove();


            window.URL.revokeObjectURL(
                url
            );

        }


        catch (error) {

            console.error(
                "REPORT ERROR:",
                error
            );


            alert(
                "Report download failed: " +
                error.message
            );

        }


        finally {

            if (reportButton) {

                reportButton.disabled =
                    false;

                reportButton.textContent =
                    "Download Report";
            }


            if (generateReportButton) {

                generateReportButton.disabled =
                    false;

                generateReportButton.textContent =
                    "Generate Report";
            }
        }
    }


    // ============================================================
    // CONNECT REPORT BUTTONS
    // ============================================================

    if (reportButton) {

        reportButton.addEventListener(
            "click",
            downloadReport
        );
    }


    if (generateReportButton) {

        generateReportButton.addEventListener(
            "click",
            downloadReport
        );
    }


    // ============================================================
    // ENTER KEY
    // ============================================================

    if (valueInput) {

        valueInput.addEventListener(
            "keydown",
            (event) => {

                if (
                    event.key === "Enter"
                ) {

                    event.preventDefault();

                    analyzeButton.click();
                }
            }
        );
    }


    // ============================================================
    // INITIAL STATE
    // ============================================================

    window.latestAnalysis = null;


    console.log(
        "SentinelRAG JavaScript loaded successfully."
    );

});