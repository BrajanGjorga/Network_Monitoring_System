# Prediction agent setup guide for Ubuntu

This guide is written for a beginner who wants to run the prediction agent inside an Ubuntu VM and test it locally before connecting it to a real external receiver.

The goal is simple:

1. Install the required tools.
2. Copy the project into the VM.
3. Create a Python virtual environment.
4. Install the Python packages.
5. Copy in the model artifacts from the training project.
6. Start the local test receiver.
7. Validate the configuration.
8. Run the agent once and then run it in watch mode.
9. Watch the logs and confirm that alerts are being sent to the test endpoint.

> The project already includes a small local test receiver. You do not need to create your own endpoint yet.

---

## 1. Prepare the Ubuntu VM

Open a terminal and update the system first.

```bash
sudo apt update
sudo apt upgrade -y
```

Install the basic packages you will need.

```bash
sudo apt install -y python3 python3-pip python3-venv tcpdump default-jre-headless git
```

If you are using a Java-based CICFlowMeter build, Java is required. The command above installs it.

---

## 2. Copy or clone the project into the VM

From your home folder, create a folder for the project.

```bash
cd ~
mkdir -p prediction-agent
```

If you already have the project files in a zip or Git repository, copy them into that folder. If you are using Git, you can clone the repository instead.

Example:

```bash
git clone <your-repository-url> ~/prediction-agent
cd ~/prediction-agent
```

If you are working from a local folder, use a copy command such as:

```bash
cp -r /path/to/your/project ~/prediction-agent
cd ~/prediction-agent
```

---

## 3. Create a Python virtual environment

It is best to keep the Python environment isolated.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

You should now see the virtual environment name at the start of your command prompt.

---

## 4. Install the Python dependencies

Inside the project folder, install the requirements.

```bash
pip install -r requirements.txt
```

If the install is slow, wait for it to finish. When it is done, you are ready to move on.

---

## 5. Find the correct network interface

The agent needs to know which network interface to capture from.

Run one of these commands:

```bash
ip -br addr
```

or:

```bash
ip link
```

You are looking for a name such as:

- eth0
- ens3
- enp0s3

Use the interface name that is active on your VM.

---

## 6. Copy the model artifacts into the model folder

The agent expects trained model files in the model folder.

Copy the exported artifacts from the training project into:

```bash
~/prediction-agent/model
```

You need these files:

- model.pkl
- scaler.pkl
- feature_columns.json
- model_metadata.json
- label_encoder.pkl (optional but recommended)

If you are using the training project that already exists in this workspace, the artifacts are likely in the training project folder under the artifacts directory.

Example:

```bash
cp /path/to/model-training/artifacts/model.pkl ~/prediction-agent/model/
cp /path/to/model-training/artifacts/scaler.pkl ~/prediction-agent/model/
cp /path/to/model-training/artifacts/feature_columns.json ~/prediction-agent/model/
cp /path/to/model-training/artifacts/model_metadata.json ~/prediction-agent/model/
cp /path/to/model-training/artifacts/label_encoder.pkl ~/prediction-agent/model/ 2>/dev/null || true
```

If you do not have these files yet, the agent will tell you that the model is missing and you will need to add them before continuing.

---

## 7. Configure the project

Open the configuration file.

```bash
nano config.json
```

You should update at least these fields:

- interface: change it to your VM interface name, for example "ens3"
- model_dir: keep it as "model"
- alert_endpoint_url: leave it as the local test receiver address unless you want to use another endpoint
- dangerous_labels: keep the default values for now
- minimum_confidence: keep it at 0.8 or adjust it if you want a lower threshold

Example values:

```json
{
  "interface": "ens3",
  "pcap_output_dir": "data/pcaps",
  "csv_output_dir": "data/csv",
  "processed_dir": "data/processed",
  "model_dir": "model",
  "alert_endpoint_url": "http://127.0.0.1:8001/alerts",
  "dangerous_labels": ["MALICIOUS", "Attack"],
  "minimum_confidence": 0.8
}
```

If you are not sure about the interface name, use the one from the earlier command.

---

## 8. Configure CICFlowMeter

The agent uses a configurable CICFlowMeter command in the config file.

Open the config file and look for the field named cicflow_command.

Example:

```json
"cicflow_command": ["java", "-jar", "CICFlowMeter.jar"]
```

If you have a different CICFlowMeter setup, replace that command with the one that works on your VM.

The important point is that the agent is designed to be flexible. You do not need to use a single exact command for every installation.

If you do not have CICFlowMeter installed yet, install it first and make sure the command is valid on your VM.

---

## 9. Start the local test receiver

This is your test endpoint for now.

Open a new terminal and go to the project folder.

```bash
cd ~/prediction-agent
source .venv/bin/activate
python test_receiver.py
```

You should see FastAPI starting. The receiver will listen on:

- http://127.0.0.1:8001/alerts

This receiver is meant only for development and testing.

You can also inspect received alerts with:

```bash
curl http://127.0.0.1:8001/alerts
```

---

## 10. Validate that the configuration is good

Back in the first terminal, run:

```bash
cd ~/prediction-agent
source .venv/bin/activate
python agent.py --validate-config
```

Then validate the model files:

```bash
python agent.py --validate-model
```

If everything is configured correctly, the agent will say that the configuration and model were validated.

If you see missing artifact errors, go back and copy the model files into the model folder.

---

## 11. Run the agent once to test the pipeline

Now try the agent in one-shot mode.

```bash
python agent.py --once
```

What should happen:

- The agent looks for PCAP files.
- It checks for completed files.
- It runs CICFlowMeter if a PCAP is ready.
- It processes the CSV output.
- It loads the model and applies the saved preprocessing.
- It predicts each flow.
- If a flow is classified as dangerous and above the confidence threshold, it sends an alert to the test endpoint.

You will see logs in the terminal showing what happened.

---

## 12. Run the agent in continuous mode

If you want the agent to keep watching for new PCAP files, run:

```bash
python agent.py --watch
```

This runs the loop repeatedly. The agent will check the capture directory, process new files, and retry any failed alerts.

To stop it, press Ctrl+C in that terminal.

---

## 13. See what is going on in the logs

The agent uses Python logging. You will see messages such as:

- detected PCAP files
- CICFlowMeter conversion results
- number of processed rows
- benign and dangerous counts
- alerts sent
- alerts queued

If you want to see more output, adjust the log level in config.json.

Example:

```json
"log_level": "DEBUG"
```

---

## 14. Check whether the alert reached the test endpoint

While the receiver is running, open another terminal and run:

```bash
curl http://127.0.0.1:8001/alerts
```

If the agent sent a dangerous alert, you will see the alert JSON in the response.

You can also read the logs from the receiver terminal to confirm the alert was received.

---

## 15. If you want to process one specific PCAP file

If you already have a PCAP file and want to process only that one, run:

```bash
python agent.py --process-pcap /path/to/your/file.pcap
```

This is useful when you want to test the pipeline quickly without starting full continuous capture.

---

## 16. If you want to process one specific CSV file

If you already have a CICFlowMeter CSV file and want to test the model logic directly, run:

```bash
python agent.py --process-csv /path/to/your/file.csv
```

---

## 17. Important beginner notes

A few things to keep in mind:

- This is near-real-time flow classification, not packet-by-packet blocking.
- A flow may only be available after it closes or times out.
- CICFlowMeter output must match the feature definitions used during training.
- Different CICFlowMeter versions may produce different columns.
- A model trained on a public dataset may not generalize perfectly to real traffic.
- The agent reports predictions; it does not automatically block traffic.
- Only capture and test traffic that you own or are authorized to monitor.

---

## 18. The easiest first test path

If you want the shortest path to a working check, follow this order:

```bash
cd ~/prediction-agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python test_receiver.py
```

In a second terminal:

```bash
cd ~/prediction-agent
source .venv/bin/activate
python agent.py --validate-config
python agent.py --validate-model
python agent.py --once
```

If you have a valid PCAP and matching model artifacts, the agent should begin processing and eventually send a dangerous alert to the local receiver if the model predicts a dangerous label.

---

## 19. Common problems

### Problem: the agent says model artifacts are missing

Fix:

- Copy the model files into the model folder.
- Make sure the file names are correct.

### Problem: the agent says the interface is wrong

Fix:

- Run `ip -br addr` again.
- Update the interface value in config.json.

### Problem: CICFlowMeter does not run

Fix:

- Check that Java is installed.
- Check that the command in config.json is correct.
- Test the CICFlowMeter command directly in the terminal.

### Problem: no alerts appear

Fix:

- Make sure the receiver is running.
- Make sure the agent is processing a file.
- Make sure the model produced a dangerous prediction above the minimum confidence threshold.

---

## 20. Summary

When you finish these steps, you should have:

- a working Python environment
- a configured agent
- a local test endpoint running
- a running agent that processes PCAP/CSV files
- alerts being delivered to the test receiver

That is the simplest way to get your project running on an Ubuntu VM and verify the flow from capture to alert delivery.
