import sys
import pandas as pd


# Function to count requests per IP address
def count_Request(file):
    counter = {}
    with open(file, 'r') as sample:
        for log in sample:
            log = list(log.split(" "))
            if log[0] in counter:
                counter[log[0]] += 1
            else:
                counter[log[0]] = 1

    # Create DataFrame from IP request counts
    counter_DataFrame = pd.DataFrame(
        [[ip, counter[ip]] for ip in counter],
        columns=['IP Address', 'Request Count']
    )
    return counter_DataFrame


# Function to identify the most frequently accessed endpoint
def frequently_Accessed_Endpoint(file):
    counter = {}
    with open(file, 'r') as sample:
        for log in sample:
            log = list(log.split(" "))
            if log[6] in counter:
                counter[log[6]] += 1
            else:
                counter[log[6]] = 1

    # Find the endpoint accessed the most
    endpoint = ""
    frequency = 0
    for i in counter:
        if counter[i] > frequency:
            frequency = counter[i]
            endpoint = i

    # Create DataFrame with the most frequently accessed endpoint
    counter_DataFrame = pd.DataFrame(
        [[f'{endpoint} (Accessed {frequency} times)']],
        columns=['Most Frequently Accessed Endpoint']
    )
    return counter_DataFrame


# Function to detect suspicious activity (failed login attempts)
def detect_Suspicious_Activity(file, login_threshold=10):
    counter = {}
    with open(file, 'r') as sample:
        for log in sample:
            log = list(log.split(" "))
            # Check for failed login keywords in the log line
            if '401' in log or ('"Invalid' in log and 'credentials"' in log):
                if log[0] in counter:
                    counter[log[0]] += 1
                else:
                    counter[log[0]] = 1

    # Filter IPs with failed attempts exceeding the threshold
    counter_DataFrame = pd.DataFrame(
        [[ip, counter[ip]] for ip in counter if counter[ip] > login_threshold],
        columns=['IP Address', 'Failed Login Attempts']
    )

    # If no suspicious IPs, create a placeholder DataFrame
    if len(counter_DataFrame) == 0:
        counter_DataFrame = pd.DataFrame(
            ["No Failed IP addresses with login attempts exceeding the threshold"]
        )
    return counter_DataFrame


# Function to generate a CSV report with all analyses
def generate_CSV(file, login_threshold):
    try:
        # Collect all analysis results
        content = [
            count_Request(file),
            frequently_Accessed_Endpoint(file),
            detect_Suspicious_Activity(file, login_threshold)
        ]

        # Append results to CSV file
        with open('log_analysis_results.csv', 'a+') as f:
            for df in content:
                df.to_csv(f, index=False)  # Save DataFrame to file
                f.write("\n")  # Separate sections with a blank line
    except Exception as e:
        return False  # Indicate failure if an error occurs
    return True  # Indicate success


# Main function to handle user input and call appropriate functions
def main():
    # Display help menu if no arguments are provided
    if len(sys.argv) == 1:
        print("'-i' '--I' To get the Count Requests per IP Address")
        print("'-f' '--F' To get the Identify the Most Frequently Accessed Endpoint")
        print("'-s' '--S' To Detect Suspicious Activity (Failed Login)")
        print("'-c' '--C' To generate the CSV (log_analysis_results.csv)")
        print("Command:")
        print("python Log_Scanner.py <file location> <tag>")
        print("Example: python Log_Scanner.py './sample.log' -i")
        sys.exit(1)

    file = sys.argv[1]  # Log file path from command line

    # If a specific analysis tag is provided
    if len(sys.argv) > 2:
        tag = sys.argv[2]

        if tag in ['-i', '--I']:
            request_counter = count_Request(file)
            print(request_counter)

        elif tag in ['-f', '--F']:
            frequent_Endpoint = frequently_Accessed_Endpoint(file)
            print(frequent_Endpoint)

        elif tag in ['-s', '--s']:
            threshold_value = 10  # Default threshold for failed logins
            try:
                if len(sys.argv) == 4:
                    threshold_value = int(sys.argv[3])  # Custom threshold
            finally:
                suspicious_activity = detect_Suspicious_Activity(file, threshold_value)
                print(suspicious_activity)

        elif tag in ['-c', '--C']:
            threshold_value = 10  # Default threshold
            try:
                if len(sys.argv) == 4:
                    threshold_value = int(sys.argv[3])  # Custom threshold
            finally:
                if generate_CSV(file, threshold_value):
                    print("log_analysis_data.log file generated successfully")
                else:
                    print("Error: File not created")

        else:
            print("Try using python Log_Scanner.py -> To open Help menu")
        sys.exit(1)

    # Default CSV generation if no specific tag is given
    else:
        if generate_CSV(file, 10):  # Default threshold
            print("log_analysis_data.log file generated successfully")
        else:
            print("Error: File not created")
        sys.exit(1)


# Entry point for the script
if __name__ == '__main__':
    main()
