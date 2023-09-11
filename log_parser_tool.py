from flask import Flask, request, send_file
import json
import xml.etree.ElementTree as ET
import csv
import re

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        file_path = file.filename
        file.save(file_path)

        parsed_data = []
        try:
            with open(file_path, 'r') as log_file:
                # Parse JSON logs
                if '.json' in file_path:
                    data_json = json.load(log_file)
                    for entry in data_json:
                        parsed_data.append({
                            'Timestamp': entry.get('Timestamp', 'Unknown'),
                            'LogLevel': entry.get('LogLevel', 'Unknown'),
                            'Component': 'Unknown',
                            'Parameter': entry.get('UserID', 'Unknown'),
                            'EventTemplate': entry.get('Action', 'Unknown'),
                            'Severity': 'Unknown'  # Not provided in JSON log example
                        })
                # Parse XML logs
                elif '.xml' in file_path:
                    tree = ET.parse(log_file)
                    root = tree.getroot()
                    for log in root:
                        parsed_data.append({
                            'Timestamp': log.find('timestamp').text,
                            'LogLevel': log.find('logLevel').text,
                            'Component': 'Unknown',
                            'Parameter': log.find('userId').text,
                            'EventTemplate': log.find('action').text,
                            'Severity': 'Unknown'  # Not provided in XML log example
                        })
                # Common log format, Extended log format, and Window event log
                elif '.txt' in file_path:
                    entries = re.findall(
                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+)', log_file.read())
                    for entry in entries:
                        method, path, protocol = entry[2].split(' ')
                        parsed_data.append({
                            'Timestamp': entry[1],
                            'LogLevel': 'Unknown',  # Doesn't provided in log lines,
                            'Component': "Unknown",
                            'Parameter': entry[0],
                            'EventTemplate': f'{method} {path}',
                            'Severity': 'Unknown'
                        })
                elif 'CEF' in file_path:
                    pattern = re.compile(
                        r"CEF:\d+\|(.+?)\|(.+?)\|(.*?)\|(.*?)\|(.*?)\|(\d)\|")
                    matches = pattern.finditer(log_file.read())
                    for match in matches:
                        parsed_data.append({
                            'Timestamp': 'Unknown',
                            'LogLevel': 'Unknown',
                            'Component': match.group(3),
                            'Parameter': 'Unknown',
                            'EventTemplate': match.group(5),
                            'Severity': match.group(6)
                        })
        except Exception as e:
            return 'Log format not supported. ' + str(e)
        # Save as CSV
        with open('parsed_logs.csv', 'w', newline='') as csvfile:
            fieldnames = ['Timestamp', 'LogLevel', 'Component',
                          'Parameter', 'EventTemplate', 'Severity']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for data in parsed_data:
                writer.writerow(data)

        return send_file('parsed_logs.csv', as_attachment=True)

    return '''
    <!doctype html>
    <html>
        <body>
            <form method="POST" enctype="multipart/form-data">
                <input type="file" name="file">
                <input type="submit">
            </form>
        </body>
    </html>
    '''


if __name__ == '__main__':
    app.run(debug=True)
