import docker
import re
from flask import Flask

app = Flask(__name__)
client = docker.from_env()

@app.route("/")
def root():
    return update_html()

def add_logs(html_code):
    adding = ""
    for container in client.containers.list():        
        adding+="> CONTAINER {}".format(container.id[:5])
        adding+=log_clean(str(container.logs()))

    return html_code + adding

def log_clean(logs):
    logs = logs.replace("b\"nohup: appending output to 'nohup.out'", "")
    logs = logs.replace("\\n", "\n")
    logs = logs.replace("\\r", "")
    logs = logs.replace("\\x1b[0m",  "")
    logs = logs.replace("\\x1b[31m", "")
    logs = logs.replace("\\x1b[32m", "")
    logs = logs.replace("\\x1b[33m", "")
    logs = logs.replace("\\x1b[34m", "")
    logs = logs.replace("\\x1b[35m", "")
    logs = logs.replace("\\x1b[36m", "")

    return logs[:-1]

def update_html():
    html_code = ""
    html_code = add_logs(html_code)
    return html_code

if __name__ == "__main__":
    #print(update_html())
    app.run()
