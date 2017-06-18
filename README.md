# Get Alerts

Create an alert report using the Threat Stack API. You can specify the Threat Stack "Org", fields, date range and a string in the alert title that identifies a specific rule set (e.g. HIPAA, PCI, SOC-2). The app can be installed on a Mac or Linux box. You can then run it from a command line to generate the report in CSV format.

## Run locally

`python get_alerts.py --auth <AUTH KEY> --org <ORG ID>`

For help:

`python get_alerts.py -H`

## Bundle Up

Use [pyinstaller](https://pythonhosted.org/PyInstaller/operating-mode.html):

`pyinstaller get_alerts.spec`.

Mac executable ends up in `dist/get_alerts`.
