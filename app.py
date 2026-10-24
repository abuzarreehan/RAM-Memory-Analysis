import os
import re
import shutil
import subprocess
import tempfile
import html
from pathlib import Path
from datetime import datetime

import streamlit as st
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

st.set_page_config(
    page_title="RAM Memory Analysis",
    page_icon="🛡️",
    layout="wide",
)

PLUGINS = [
    ("System Information", "windows.info"),
    ("Process List", "windows.pslist"),
    ("Process Scan", "windows.psscan"),
    ("Process Tree", "windows.pstree"),
    ("Command Lines", "windows.cmdline"),
    ("DLL List", "windows.dlllist"),
    ("Network Connections", "windows.netscan"),
    ("Services", "windows.svcscan"),
    ("Suspicious Memory Regions", "windows.malfind"),
    ("Virtual Memory Regions", "windows.vadinfo"),
]

# -------------------- DASHBOARD --------------------

st.title("🛡️ RAM Memory Analysis Dashboard")
st.caption("Automated memory forensics powered by Volatility 3")

with st.sidebar:
    st.header("Case Details")
    case_name = st.text_input(
        "Case / Project Name", "RAM Memory Analysis"
    )
    analyst = st.text_input("Analyst", "Student Analyst")
    st.info(
        "Analyze only memory images you are authorized to examine."
    )

st.subheader("1. Select Memory Image")

uploaded = st.file_uploader(
    "Upload a memory dump",
    type=["mem", "raw", "dmp", "vmem", "lime", "bin"],
    help="For large files, enter a local path instead.",
)

local_path = st.text_input(
    "Or enter local dump path",
    placeholder=(
        r"C:\Users\reeha\RAM-Memory-Analysis"
        r"\datasets\WinDump\WinDump.mem"
    ),
    key="local_dump_path",
)

st.caption(
    "Choose either a file upload or a local path. "
    "A local path must exist on the computer running Streamlit."
)

run_selected = st.multiselect(
    "Plugins to run",
    options=[plugin for _, plugin in PLUGINS],
    default=[plugin for _, plugin in PLUGINS],
    format_func=lambda value: next(
        (label for label, plugin in PLUGINS if plugin == value),
        value,
    ),
)

timeout_minutes = st.slider(
    "Timeout per plugin (minutes)", 1, 60, 10
)

if "results" not in st.session_state:
    st.session_state.results = {}

if "dump_name" not in st.session_state:
    st.session_state.dump_name = ""

if "findings" not in st.session_state:
    st.session_state.findings = []


# -------------------- VOLATILITY --------------------

def find_volatility():
    return shutil.which("vol") or shutil.which("vol.exe")


def run_plugin(vol_cmd, dump_path, plugin, timeout_seconds):
    command = [vol_cmd, "-f", str(dump_path), plugin]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            shell=False,
        )

        output = process.stdout or ""

        if process.stderr:
            output += (
                "\n\n--- STDERR / DIAGNOSTICS ---\n"
                + process.stderr
            )

        return {
            "status": (
                "Completed"
                if process.returncode == 0
                else "Completed with warnings/errors"
            ),
            "returncode": process.returncode,
            "output": output.strip() or "(No output returned.)",
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "Timed out",
            "returncode": -1,
            "output": f"Plugin exceeded {timeout_seconds} seconds.",
        }

    except Exception as exc:
        return {
            "status": "Failed to start",
            "returncode": -2,
            "output": str(exc),
        }


# -------------------- AUTOMATED FINDINGS --------------------

def parse_pids(text):
    found = set()

    for line in text.splitlines():
        match = re.match(
            r"\s*(\d+)\s+([A-Za-z0-9_.-]+)",
            line,
        )

        if match:
            found.add(match.group(1))

    return found


def make_findings(results):
    findings = []

    malfind_output = results.get(
        "windows.malfind", {}
    ).get("output", "")

    if "PAGE_EXECUTE_READWRITE" in malfind_output:
        findings.append(
            (
                "Review",
                "Executable-writable memory indicator",
                "The malfind output contains PAGE_EXECUTE_READWRITE.",
                (
                    "This may be associated with injected code, but "
                    "legitimate runtime or JIT activity can also use "
                    "such memory. Validate memory contents and "
                    "process context."
                ),
            )
        )

    psscan_output = results.get(
        "windows.psscan", {}
    ).get("output", "")

    pslist_output = results.get(
        "windows.pslist", {}
    ).get("output", "")

    if psscan_output and pslist_output:
        scan_pids = parse_pids(psscan_output)
        list_pids = parse_pids(pslist_output)

        difference = sorted(
            scan_pids - list_pids,
            key=lambda pid: int(pid),
        )

        if difference:
            findings.append(
                (
                    "Review",
                    f"{len(difference)} possible scan-only process PID(s)",
                    ", ".join(difference[:25]),
                    (
                        "These differences may reflect terminated "
                        "processes, pool-scan artifacts, or parsing "
                        "differences. This alone does not prove malware."
                    ),
                )
            )

    network_output = results.get(
        "windows.netscan", {}
    ).get("output", "")

    if network_output:
        ips = sorted(
            set(
                re.findall(
                    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                    network_output,
                )
            )
        )

        if ips:
            findings.append(
                (
                    "Context required",
                    f"{len(ips)} IP address(es) in network output",
                    ", ".join(ips[:15]),
                    (
                        "IP addresses alone are not malicious. "
                        "Check process ownership, connection state, "
                        "destination reputation, and capture date."
                    ),
                )
            )

    failed_plugins = [
        plugin
        for plugin, result in results.items()
        if result["returncode"] != 0
    ]

    if failed_plugins:
        findings.append(
            (
                "Information",
                f"{len(failed_plugins)} plugin(s) had errors or timed out",
                ", ".join(failed_plugins),
                (
                    "Review plugin diagnostics. Failed plugins "
                    "may leave gaps in the analysis."
                ),
            )
        )

    if not findings:
        findings.append(
            (
                "Informational",
                "No simple indicators matched",
                "No configured text checks matched.",
                (
                    "This does not prove that the memory image is "
                    "clean. Review the plugin outputs and warnings."
                ),
            )
        )

    return findings


# -------------------- PDF REPORT --------------------

def create_pdf(results, findings, dump_name):
    temp = tempfile.NamedTemporaryFile(
        delete=False, suffix=".pdf"
    )
    temp.close()

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="SmallReport",
            parent=styles["BodyText"],
            fontSize=7,
            leading=9,
        )
    )

    escape = lambda value: html.escape(str(value))

    story = [
        Paragraph(
            "RAM Memory Analysis Report",
            styles["Title"],
        ),
        Spacer(1, 5 * mm),
        Paragraph(
            f"<b>Case:</b> {escape(case_name)}",
            styles["BodyText"],
        ),
        Paragraph(
            f"<b>Analyst:</b> {escape(analyst)}",
            styles["BodyText"],
        ),
        Paragraph(
            f"<b>Memory Image:</b> {escape(dump_name)}",
            styles["BodyText"],
        ),
        Paragraph(
            f"<b>Generated:</b> {datetime.now():%Y-%m-%d %H:%M:%S}",
            styles["BodyText"],
        ),
        Spacer(1, 4 * mm),
        Paragraph("Executive Summary", styles["Heading2"]),
        Paragraph(
            "This report summarizes automated Volatility 3 output "
            "and basic triage indicators. It is not a definitive "
            "malware verdict.",
            styles["BodyText"],
        ),
        Spacer(1, 3 * mm),
        Paragraph("Automated Findings", styles["Heading2"]),
    ]

    table_data = [
        ["Severity", "Finding", "Evidence", "Interpretation"]
    ]

    for severity, finding, evidence, interpretation in findings:
        table_data.append(
            [
                Paragraph(escape(severity), styles["SmallReport"]),
                Paragraph(escape(finding), styles["SmallReport"]),
                Paragraph(escape(evidence), styles["SmallReport"]),
                Paragraph(
                    escape(interpretation),
                    styles["SmallReport"],
                ),
            ]
        )

    table = Table(
        table_data,
        repeatRows=1,
        colWidths=[27 * mm, 48 * mm, 65 * mm, 100 * mm],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#17365D"),
                ),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    story.extend(
        [
            table,
            Spacer(1, 4 * mm),
            Paragraph(
                "Plugin Execution Summary",
                styles["Heading2"],
            ),
        ]
    )

    plugin_data = [["Plugin", "Status", "Exit Code"]]

    for plugin, result in results.items():
        plugin_data.append(
            [
                plugin,
                result["status"],
                str(result["returncode"]),
            ]
        )

    plugin_table = Table(
        plugin_data,
        repeatRows=1,
        colWidths=[80 * mm, 100 * mm, 35 * mm],
    )

    plugin_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#D9EAF7"),
                ),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )

    story.extend(
        [
            plugin_table,
            PageBreak(),
            Paragraph(
                "Detailed Plugin Output (truncated per plugin)",
                styles["Heading2"],
            ),
        ]
    )

    for plugin, result in results.items():
        output = escape(result["output"][:9000])
        output = output.replace("\n", "<br/>")

        story.extend(
            [
                Paragraph(escape(plugin), styles["Heading3"]),
                Paragraph(output or "(No output)", styles["SmallReport"]),
                Spacer(1, 3 * mm),
            ]
        )

    story.append(
        Paragraph(
            "Limitations: a flag is not proof of malware, and absence "
            "of a flag is not proof of a clean system. Results depend "
            "on image compatibility, symbols, and plugin support.",
            styles["SmallReport"],
        )
    )

    SimpleDocTemplate(
        temp.name,
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
    ).build(story)

    with open(temp.name, "rb") as file:
        pdf_bytes = file.read()

    os.remove(temp.name)
    return pdf_bytes


# -------------------- CORRECTED FILE VALIDATION --------------------

def get_dump_source(uploaded_file, entered_path):
    # Check upload first.
    if uploaded_file is not None:
        return "upload", uploaded_file.name

    # Correctly normalize the entered local path.
    path_text = (entered_path or "").strip().strip('"').strip("'")

    if not path_text:
        return None, (
            "Please upload a memory dump or enter a local file path."
        )

    path_text = os.path.expandvars(path_text)
    path = Path(path_text).expanduser()

    if not path.exists():
        return None, f"File not found: {path}"

    if not path.is_file():
        return None, f"The supplied path is not a file: {path}"

    return path, path.name


# -------------------- RUN ANALYSIS --------------------

if st.button(
    "🚀 Run Automated Analysis",
    type="primary",
    use_container_width=True,
):
    source, source_name = get_dump_source(
        uploaded,
        local_path,
    )

    if source is None:
        st.error(source_name)
        st.info(
            "Verify the complete path and confirm the file exists "
            "on the computer running Streamlit."
        )

    elif not run_selected:
        st.error("Select at least one plugin.")

    else:
        volatility = find_volatility()

        if not volatility:
            st.error(
                "The 'vol' command was not found. Run 'vol -h' in "
                "the same terminal, then start Streamlit from that "
                "terminal."
            )

        else:
            temporary_dump = None

            try:
                if source == "upload":
                    suffix = Path(uploaded.name).suffix or ".mem"

                    with tempfile.NamedTemporaryFile(
                        delete=False,
                        suffix=suffix,
                    ) as file:
                        file.write(uploaded.getbuffer())
                        temporary_dump = file.name

                    dump_path = temporary_dump
                    dump_name = uploaded.name

                else:
                    dump_path = source
                    dump_name = source_name

                results = {}
                progress = st.progress(0)
                status = st.empty()

                for index, plugin in enumerate(
                    run_selected, start=1
                ):
                    status.write(
                        f"Running {plugin} "
                        f"({index}/{len(run_selected)})..."
                    )

                    results[plugin] = run_plugin(
                        volatility,
                        dump_path,
                        plugin,
                        timeout_minutes * 60,
                    )

                    progress.progress(
                        int(index / len(run_selected) * 100)
                    )

                status.success(
                    "Analysis finished. Review warnings, errors, "
                    "and timeouts below."
                )

                st.session_state.results = results
                st.session_state.dump_name = dump_name
                st.session_state.findings = make_findings(results)

            finally:
                if (
                    temporary_dump
                    and os.path.exists(temporary_dump)
                ):
                    try:
                        os.remove(temporary_dump)
                    except OSError:
                        pass


# -------------------- RESULTS AND DOWNLOADS --------------------

if st.session_state.results:
    results = st.session_state.results
    findings = st.session_state.findings

    st.divider()
    st.subheader("2. Analysis Overview")

    col1, col2, col3 = st.columns(3)

    col1.metric("Plugins Run", len(results))
    col2.metric(
        "Successful",
        sum(
            1
            for result in results.values()
            if result["returncode"] == 0
        ),
    )
    col3.metric(
        "Items Requiring Review",
        sum(
            1
            for item in findings
            if item[0] in ("Review", "Context required")
        ),
    )

    st.subheader("3. Automated Findings")
    st.warning(
        "These are triage indicators, not confirmed malware verdicts."
    )

    for severity, title, evidence, interpretation in findings:
        with st.expander(
            f"{severity}: {title}",
            expanded=True,
        ):
            st.write("**Evidence:**", evidence)
            st.write("**Interpretation:**", interpretation)

    st.subheader("4. Plugin Results")

    selected_plugin = st.selectbox(
        "View plugin output",
        list(results.keys()),
    )

    selected_result = results[selected_plugin]

    st.caption(
        f'{selected_result["status"]} | '
        f'Exit code: {selected_result["returncode"]}'
    )

    st.code(
        selected_result["output"][:30000],
        language="text",
    )

    full_text = "\n\n".join(
        f"### {plugin} | {result['status']} "
        f"| exit={result['returncode']}\n{result['output']}"
        for plugin, result in results.items()
    )

    st.download_button(
        "Download All Plugin Output (.txt)",
        data=full_text.encode("utf-8", errors="replace"),
        file_name="ram_memory_analysis_outputs.txt",
        mime="text/plain",
    )

    pdf_data = create_pdf(
        results,
        findings,
        st.session_state.dump_name,
    )

    st.download_button(
        "📄 Download Final Forensic Report (PDF)",
        data=pdf_data,
        file_name="RAM_Memory_Analysis_Report.pdf",
        mime="application/pdf",
        type="primary",
        use_container_width=True,
    )

else:
    st.info(
        "Enter the local dump path or upload a dump, "
        "then click Run Automated Analysis."
    )

st.caption(
    "Keep raw memory dumps and sensitive evidence out of public GitHub repositories."
)