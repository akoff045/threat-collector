Threat Collector
Overview

Threat Collector is a Python-based tool designed to automate the collection of Indicators of Compromise (IOCs) from AlienVault's Open Threat Exchange (OTX). It fetches threat intelligence data, processes it, and generates analytical reports to aid in cybersecurity defense strategies.

Features

Automated IOC Collection: Retrieves IOCs from OTX using their public API.

Data Processing: Parses and structures threat data into CSV format for easy analysis.

Analytical Reporting: Utilizes analyzer.py to generate statistical summaries and visual representations of the collected data.

Modular Design: Consists of separate modules for data collection and analysis, promoting maintainability and scalability.

Technologies Used

Programming Language: Python 3.8+

Libraries:

requests: For making HTTP requests to the OTX API.

pandas: For data manipulation and CSV handling.

matplotlib & seaborn: For data visualization and generating reports.

Data Format: CSV for structured data output.