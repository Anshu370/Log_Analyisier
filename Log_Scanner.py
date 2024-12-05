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
    pass

def detect_Suspicious_Activity(file):
    pass

def generate_CSV(file):
    return True

def main():

    file = sys.argv[1]

    if file in ["help", "-h", "--H"] or len(sys.argv) < 1:
        print("'-i' '--I' To get the Count Requests per IP Address")
        print("'-f' '--F' To get the Identify the Most Frequently Accessed Endpoint")
        print("'-s' '--S' To Detect Suspicious Activity(Failed Login)")
        print("'-a' '--A' To Conduct all test at same time")
        print("'-c' '--C' To generate the CSV(log_analysis_results.csv)")
        print("Command")
        print("python Log_Scanner.py <file location> <tag>")
        print("Example :- python Log_Scanner.py './sample.log' -i")
        sys.exit(1)

    if len(sys.argv) > 2:
        tag = sys.argv[2]
        if tag in ['-i', '--I']:
            request_counter = count_Request(file)
            print(request_counter)

        elif tag in ['-f', '--F']:
            frequent_Endpoint = frequently_Accessed_Endpoint(file)
            print(frequent_Endpoint)

        elif tag in ['-a', '--A']:
            suspicious_activity = detect_Suspicious_Activity(file)
            print(suspicious_activity)
        elif tag in ['-c', '--C']:
            if generate_CSV(file):
                print("log_analysis_data.log file generated successfully")
            else:
                print("Some error File not created")
        else:
            request_counter = count_Request(file)
            frequent_Endpoint = frequently_Accessed_Endpoint(file)
            suspicious_activity = detect_Suspicious_Activity(file)
            if generate_CSV(file):
                print("log_analysis_data.log file generated successfully")
                print(request_counter)
                print(frequent_Endpoint)
                print(suspicious_activity)
            else:
                print("Some error File not created")
        sys.exit(1)
    else:
        if generate_CSV(file):
            print("log_analysis_data.log file generated successfully")
        else:
            print("Some error File not created")
        sys.exit(1)




if __name__ == '__main__':
    main()
    # count_Request('./sample.log')
