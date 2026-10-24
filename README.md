# RAM Memory Analysis

A digital forensics project for analyzing RAM memory dumps, extracting forensic artifacts, identifying suspicious indicators, and generating investigation reports using **Volatility 3 and Streamlit**.

## About the Project

RAM Memory Analysis is a cybersecurity and digital forensics project that investigates the contents of a captured computer memory image. It helps analyze running and previously detected processes, loaded DLLs, memory regions, network connections, and Windows services.

The project provides a Streamlit-based dashboard so users can run selected forensic plugins and review their results through a single interface. It can also generate a downloadable PDF report containing the analysis results.

## Objectives

- Analyze captured RAM memory images.
- Extract system and operating system information.
- Examine processes and parent-child process relationships.
- Investigate loaded DLLs and virtual memory regions.
- Examine network connection artifacts and Windows services.
- Highlight potentially suspicious memory artifacts for further investigation.
- Generate reports to document findings and limitations.

## Technologies Used

- **Python** — application development and analysis workflow.
- **Volatility 3** — memory forensics framework.
- **Streamlit** — interactive web dashboard.
- **Pandas** — tabular data handling, where applicable.
- **ReportLab** — PDF report generation.

## Features

- Upload a memory dump or provide a local file path.
- Run selected Volatility 3 plugins.
- Review process and system information.
- Examine network connections and Windows services.
- Investigate DLL information and virtual memory regions.
- Identify potentially suspicious memory artifacts.
- View analysis output and download a forensic report.

## Memory Forensics Modules

| Plugin | Purpose |
|---|---|
| `windows.info` | Extract operating system and memory-image information |
| `windows.pslist` | List processes recovered from memory |
| `windows.psscan` | Scan memory for process artifacts |
| `windows.pstree` | Examine parent-child process relationships |
| `windows.cmdline` | Retrieve available process command-line information |
| `windows.dlllist` | Examine DLLs associated with processes |
| `windows.netscan` | Examine network connection artifacts |
| `windows.svcscan` | Scan for Windows service artifacts |
| `windows.malfind` | Identify memory regions with characteristics that may indicate code injection |
| `windows.vadinfo` | Examine virtual address descriptor and memory-region information |

Plugin availability and output depend on the memory image, operating system, symbols, and Volatility 3 support.

## Project Workflow

1. Select or upload a captured RAM memory dump.
2. Choose the forensic analysis modules.
3. Execute the selected Volatility 3 plugins.
4. Review extracted artifacts and potential indicators.
5. Investigate unusual findings using additional context.
6. Generate and download the PDF forensic report.

## Project Structure

```text
RAM-Memory-Analysis/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── datasets/
│   └── WinDump/
│       └── WinDump.mem
├── process_analysis/
├── dll_analysis/
├── network_analysis/
├── reports/
├── screenshots/
└── docs/
```

This is a suggested structure. Keep any additional folders required by the current application.

## Installation and Setup

### Prerequisites

- Python 3.10 or a compatible Python version supported by the installed dependencies.
- Git (optional).
- A compatible RAM memory dump.
- Windows, Linux, or another environment supported by the required tools.

### 1. Clone the repository

```bash
git clone https://github.com/abuzarreehan/RAM-Memory-Analysis.git
cd RAM-Memory-Analysis
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

Ensure that the Volatility 3 command-line tool is installed and available in your environment. The application uses it to execute forensic plugins.

### 4. Run the application

```bash
streamlit run app.py
```

Open the local URL displayed in the terminal by Streamlit.

### 5. Analyze a memory dump

Upload a supported memory image or enter its local path in the dashboard, select the required analysis plugins, and run the analysis.

## Results and Reporting

The application presents the output returned by the selected forensic plugins and provides a PDF report for documenting the investigation.

Potential indicators may include unusual executable-writable memory regions, differences between process-listing methods, unexpected network artifacts, or other findings requiring additional investigation.

**An indicator is not proof of malware.** Findings should be validated using process context, memory mappings, file paths, related artifacts, and other available forensic evidence.

## Dataset and Safety

This project uses captured memory images for forensic investigation. The current development sample is `WinDump.mem`.

Memory dumps can contain sensitive information, including credentials, personal data, and fragments of application content. Use authorized datasets and do not publish memory dumps or confidential evidence in the public repository.

Large memory images and generated investigation artifacts should be stored locally unless they are explicitly approved for sharing.

## Limitations

- Analysis depends on memory-image compatibility and available symbols.
- Some plugins may return incomplete results or errors for particular images.
- Heuristic indicators can produce false positives.
- Missing indicators do not guarantee that a system is free from malware.
- The application assists forensic investigation; it does not independently prove that a system is infected.

## Future Enhancements

- Add additional documented memory-forensics datasets, including known-malware samples.
- Improve suspicious-artifact correlation across multiple plugins.
- Add filtering, search, and structured evidence summaries.
- Improve report formatting and investigation metadata.
- Compare findings from baseline and known-malware memory images.

## Disclaimer

This project is intended for educational purposes, cybersecurity learning, and authorized digital forensic investigations. Analyze only memory images you are authorized to examine.

## Author

**Abu Zar Reehan**

GitHub: https://github.com/abuzarreehan/RAM-Memory-Analysis
