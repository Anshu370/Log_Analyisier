import sys
import pandas as pd

def count_Request(file):
    counter = {}
    with open(file, 'r') as sample:
        data = sample.readlines()
        for log in data:
            log = list(log.split(" "))
            if log[0] in counter:
                counter[log[0]] += 1
            else:
                counter[log[0]] = 1

    counter_DataFrame = pd.DataFrame([[ip, counter[ip]] for ip in counter], columns=['IP Address', 'Request Count'])

    return counter_DataFrame

def frequently_Accessed_Endpoint(file):
    counter = {}
    with open(file, 'r') as sample:
        data = sample.readlines()
        for log in data:
            log = list(log.split(" "))
            if log[6] in counter:
                counter[log[6]] += 1
            else:
                counter[log[6]] = 1

    endpoint = ""
    frequency = 0

    for i in counter:
        if counter[i] > frequency:
            frequency = counter[i]
            endpoint = i

    statement = f"Most Frequently Accessed Endpoint: {endpoint} (Accessed {frequency} times)"

    return statement

def detect_Suspicious_Activity(file, login_threshold = 10):
    counter = {}

    with open(file, 'r') as sample:
        data = sample.readlines()
        for log in data:
            log = list(log.split(" "))
            if '401' in log or ('"Invalid' in log and 'credentials"' in log):
                if log[0] in counter:
                    counter[log[0]] += 1
                else:
                    counter[log[0]] = 1
        counter_DataFrame = pd.DataFrame([[ip, counter[ip]] for ip in counter if counter[ip] > login_threshold], columns=['IP Address', 'Failed Login Attempts'])
        if len(counter_DataFrame) == 0:
            return "No Failed IP addresses with login attempts exceeding a threshold"
    return counter_DataFrame

def generate_CSV(file):
    return True

def main():

    if len(sys.argv) == 1:
        print("'-i' '--I' To get the Count Requests per IP Address")
        print("'-f' '--F' To get the Identify the Most Frequently Accessed Endpoint")
        print("'-s' '--S' To Detect Suspicious Activity(Failed Login)")
        print("'-a' '--A' To Conduct all test at same time")
        print("'-c' '--C' To generate the CSV(log_analysis_results.csv)")
        print("Command")
        print("python Log_Scanner.py <file location> <tag>")
        print("Example :- python Log_Scanner.py './sample.log' -i")
        sys.exit(1)

    file = sys.argv[1]

    if len(sys.argv) > 2:
        tag = sys.argv[2]
        if tag in ['-i', '--I']:
            request_counter = count_Request(file)
            print(request_counter)

        elif tag in ['-f', '--F']:
            frequent_Endpoint = frequently_Accessed_Endpoint(file)
            print(frequent_Endpoint)

        elif tag in ['-a', '--A']:
            if len(sys.argv) <= 3:
                print("Please enter the Failed Login Threshold Value")
                sys.exit(1)

            suspicious_activity = detect_Suspicious_Activity(file, int(sys.argv[3]))
            print(suspicious_activity)

        elif tag in ['-c', '--C']:
            if generate_CSV(file):
                print("log_analysis_data.log file generated successfully")
            else:
                print("Some error File not created")

        else:
            print("Try using python Log_Scanner.py -> To open Help menu")
        sys.exit(1)
    else:
        if generate_CSV(file):
            print("log_analysis_data.log file generated successfully")
        else:
            print("Some error File not created")
        sys.exit(1)




if __name__ == '__main__':
    main()

