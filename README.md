# **Log Analyzer Script**  

## **Overview**  
This Python-based log analyzer processes web server logs to extract valuable insights. It counts requests per IP address, identifies the most frequently accessed endpoint, and detects suspicious activity such as failed login attempts. The results can be displayed in the console or saved to a CSV file.  

---

## **Features**  
- **Request Count per IP Address:** Tracks how many requests were made by each IP.  
- **Most Frequently Accessed Endpoint:** Finds the most visited web endpoint.  
- **Suspicious Activity Detection:** Detects IP addresses with repeated failed login attempts.  
- **CSV Report Generation:** Saves the analysis results into a CSV file.  
- **Efficient Processing:** Supports large files with minimal memory usage.  
- **Robust Error Handling:** Manages empty files and unexpected formats gracefully.  

---

## **Installation**  
1. **Clone the Repository:**  
   ```bash
   git clone https://github.com/yourusername/log-analyzer.git
   cd log-analyzer

---

## **Usage**  

1. **Command Format:**  
   ```bash
    python Log_Scanner.py <file_path> <tag> [login_threshold]

2. **Available Tags:**  

- `-i` or `--I` : Count requests per IP address  
- `-f` or `--F` : Identify the most frequently accessed endpoint  
- `-s` or `--S` : Detect suspicious activity (failed logins)  
- `-c` or `--C` : Generate a CSV report

---

### **Example Commands:**  

- **Count requests per IP address:**  
  ```bash
  python Log_Scanner.py ./sample.log -i  

- **Identify the most frequently accessed endpoint:**
  ```bash
  python Log_Scanner.py ./sample.log -f  

- **Detect suspicious activity with a login threshold of 5:**
  ```bash
  python Log_Scanner.py ./sample.log -s 5  

- **Generate a CSV report:**
  ```bash
  python Log_Scanner.py ./sample.log -c

---

### **CSV Output Format:**  
The CSV file `log_analysis_results.csv` includes:

- Request counts per IP address  
- The most frequently accessed endpoint  
- Suspicious IP addresses with failed login attempts  

---

### **Contributing**  
Feel free to submit issues, fork the repo, and submit pull requests. Contributions are welcome!

---

### **License**  
This project is licensed under the MIT License. See the LICENSE file for details.

---

### **Acknowledgments**  
Thanks to all contributors and the open-source community for their support.

---

### **Happy Logging!** 🚀
