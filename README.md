# Py-Log-BruteForce-Detector
A Python-based Blue Team utility for active security monitoring, parsing web server access logs to identify and report potential brute-force attacks via 401 status code aggregation.

✅ Data Handling : Efficient Data Aggregation: Uses a Python dictionary to create an in-memory lookup table, allowing for the unique tracking and aggregation of failed attempts per source IP address without relying on external databases.

✅ Threat Detection Policy : Policy-Based Threat Detection: Implements a custom threshold policy to monitor for the 401 (Unauthorized) HTTP status code, enabling real-time detection and alerting for potential brute-force attacks against target endpoints.

✅ Code Robustness : Robust File Handling & Dynamic Input: Ensures data integrity through robust file path validation and uses the simple Python input() function to dynamically accept log file paths from the user, prioritizing ease of use and error prevention.

<img width="1154" height="896" alt="image" src="https://github.com/user-attachments/assets/0b16e631-b955-4a4f-aefc-ceb351dc5be7" /> <img width="1067" height="906" alt="image" src="https://github.com/user-attachments/assets/58ad1bc7-18b5-4c95-8b13-4c9a5b49aed4" />

