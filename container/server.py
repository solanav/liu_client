import docker
import re
from flask import Flask

app = Flask(__name__)
client = docker.from_env()

@app.route("/")
def root():
    return update_html()

def add_header(html_code):
    return html_code+"""
<html>
<head>
<title>Docker logs</title>
<meta http-equiv="Refresh" content="1">
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
</head>
<body>
<div class="card-columns">"""

def add_logs(html_code):
    adding = ""
    for container in client.containers.list():        
        adding+="""
<div class="card">
<div class=\"card-body\">
<h5 class=\"card-title\">{}</h5>
<p class=\"card-text\">{}</p>
</div>
</div>\n\n""".format(str(container.id[:5]), log_clean(str(container.logs())))

    return html_code + adding

def log_clean(logs):
    logs = logs.replace("b\"nohup: appending output to 'nohup.out'", "")
    logs = logs.replace("\\n", "<br>\n")
    logs = logs.replace("\\r", "")
    logs = logs.replace("\\x1b[0m", "</font>")
    logs = logs.replace("\\x1b[31m", "<font color=\"red\">")
    logs = logs.replace("\\x1b[32m", "<font color=\"green\">")
    logs = logs.replace("\\x1b[33m", "<font color=\"orange\">")
    logs = logs.replace("\\x1b[34m", "<font color=\"blue\">")
    logs = logs.replace("\\x1b[35m", "<font color=\"magenta\">")
    logs = logs.replace("\\x1b[36m", "<font color=\"blue\">")

    logs_lines = logs.split("<br>")

    return '<br>'.join(logs_lines[-20:])[:-1]

def add_footer(html_code):
    return html_code + "</div></body></html>"

def update_html():
    html_code = ""
    html_code = add_header(html_code)
    html_code = add_logs(html_code)
    html_code = add_footer(html_code)
    return html_code

if __name__ == "__main__":
    #print(update_html())
    app.run()
