# Prediction agent project overview

This document explains the files in the prediction-agent project, how they connect, and how the whole flow works from capture to alert delivery.

The project is meant to be simple and beginner-friendly. It is not a full production IDS platform. It is a small example of a flow-classification pipeline that runs on one Ubuntu machine.

---

## 1. What the project is doing

The project follows this basic flow:

1. A capture process uses tcpdump to create PCAP files.
2. Completed PCAP files are handed to CICFlowMeter.
3. CICFlowMeter creates CSV files.
4. A Python agent reads the CSV files.
5. The saved model artifacts are loaded.
6. Each flow is classified as benign or dangerous.
7. Dangerous predictions are sent to an HTTP endpoint.

In simple terms, the agent is a small network-flow prediction helper.

---

## 2. Project structure

The main files are:

- agent.py
- capture.py
- cicflow_runner.py
- csv_processor.py
- predictor.py
- alert_sender.py
- state.py
- config.json
- requirements.txt
- test_receiver.py
- README.md

There are also folders such as:

- model/
- data/
- scripts/
- tests/

---

## 3. How the files work together

Here is the easiest mental model:

- agent.py is the main controller.
- capture.py handles packet capture.
- cicflow_runner.py converts PCAP files into CSV files.
- csv_processor.py prepares CSV rows so they can be used by the model.
- predictor.py loads the saved model and makes predictions.
- alert_sender.py sends alerts to the endpoint.
- state.py remembers which files were already processed and which alerts are still waiting to be retried.
- config.json stores the settings.
- test_receiver.py is a simple local endpoint for development testing.

So the project is basically a pipeline:

capture -> convert -> process -> predict -> send alert

---

## 4. File-by-file explanation

### agent.py

Purpose:
This is the main entry point of the application.

What it does:
- loads the configuration from config.json
- sets up logging
- creates the predictor, alert sender, and state store
- runs the main processing loop
- supports commands such as:
  - --once
  - --watch
  - --validate-config
  - --validate-model
  - --process-pcap
  - --process-csv

Main functions:

- load_config(path)
  - reads the JSON configuration file.
  - this is the first thing the agent needs before doing anything.

- configure_logging(level)
  - sets up simple Python logging so you can see what is happening.

- process_pcap_file(pcap_path, config, logger, state, predictor, alert_sender)
  - runs the full workflow for one PCAP file.
  - checks whether the file was already processed.
  - calls the CICFlowMeter runner.
  - processes the generated CSV.
  - predicts each row.
  - sends alerts when needed.

- validate_model(config, logger)
  - checks whether the model artifacts exist and can be loaded.

- validate_config(config, logger)
  - checks whether the required configuration values are present.

- main()
  - parses command line arguments.
  - starts the correct mode.

Why it is important:
This is the orchestration file. Without it, the other modules would not know when to run.

---

### capture.py

Purpose:
This file is responsible for starting and stopping the tcpdump capture process.

What it does:
- builds a tcpdump command
- uses a network interface from the config file
- writes rotated PCAP files
- starts the process in a safe way
- stops the process cleanly when needed

Main class:

- CaptureManager

Main methods:

- build_command()
  - creates the tcpdump command list.
  - it uses the configured interface and output directory.
  - it also uses rotation settings from the config file.

- start()
  - launches the tcpdump process.
  - this is the moment the packet capture begins.

- stop()
  - stops tcpdump cleanly.
  - if needed, it force-kills the process after a timeout.

Why it is important:
This file is the first step in the pipeline. It creates the raw traffic capture files that everything else depends on.

---

### cicflow_runner.py

Purpose:
This file runs CICFlowMeter on a completed PCAP file.

What it does:
- receives a PCAP file path
- runs CICFlowMeter using subprocess
- uses an argument list rather than shell=True
- captures output and errors
- checks that a CSV file was created

Main class:

- CICFlowRunner

Main method:

- run(pcap_path)
  - checks that the PCAP file exists
  - builds the CICFlowMeter command from the config
  - runs the process with a timeout
  - checks the exit code
  - confirms that the CSV file exists

Why it is important:
This file turns raw packet capture data into flow-based CSV data, which is what the model expects.

---

### csv_processor.py

Purpose:
This file prepares the CICFlowMeter CSV rows for the model.

What it does:
- loads the CSV file
- strips whitespace from column names
- removes empty rows
- removes the label column if present
- makes sure the required feature columns are present
- converts values to numbers where possible
- replaces infinity-like values with missing values
- returns a cleaned row structure for the predictor

Main class:

- CSVProcessor

Main methods:

- prepare_row(row)
  - checks the required feature columns
  - converts values into numeric form where possible
  - handles missing or invalid values in a simple way

- process_csv(csv_path)
  - reads the CSV file and returns the rows ready for prediction

Why it is important:
The model cannot use raw CSV data directly unless it is cleaned and arranged in the correct order.

---

### predictor.py

Purpose:
This file loads the saved model artifacts and uses them to classify flows.

What it does:
- loads the model file
- loads the preprocessing object
- loads feature column names
- optionally loads the label encoder
- reads metadata about the model
- validates that the required artifacts exist

Main class:

- Predictor

Main methods:

- _load()
  - loads the model artifacts from disk once when the class is created

- validate()
  - checks if the model is usable
  - verifies that the metadata and feature list look correct

- predict(row)
  - prepares the row into the expected feature shape
  - applies preprocessing if needed
  - runs the model
  - returns the prediction label and confidence

- is_dangerous_label(label, dangerous_labels)
  - decides whether a prediction should be treated as dangerous

- meets_confidence_threshold(confidence, minimum_confidence)
  - checks whether the confidence is high enough to send an alert

Why it is important:
This is the decision-making part of the system.

---

### alert_sender.py

Purpose:
This file sends alerts to the HTTP endpoint.

What it does:
- creates a unique event ID
- builds the JSON payload
- sends the payload to the configured webhook or endpoint
- retries failed sends a small number of times
- stores failed alerts locally in SQLite
- retries later when the agent runs again

Main class:

- AlertSender

Main methods:

- build_payload(prediction, confidence, metadata, model_version)
  - creates the alert JSON body

- send_alert(payload)
  - sends the alert with requests
  - returns True or False depending on success

- queue_alert(payload)
  - stores a failed alert in the local SQLite queue

- get_queued_alert_count()
  - returns how many alerts are waiting

- retry_queued_alerts()
  - tries to send alerts that failed previously

Why it is important:
Without this file, the agent would classify traffic but would never report dangerous results to an endpoint.

---

### state.py

Purpose:
This file stores simple state in a local SQLite database.

What it does:
- remembers which PCAP files were already processed
- remembers which CSV files were already processed
- stores alerts waiting for retry
- stores timestamps and simple error information

Main class:

- StateStore

Main methods:

- mark_pcap_processed(path)
  - records a PCAP file as processed

- mark_csv_processed(path)
  - records a CSV file as processed

- is_pcap_processed(path)
  - checks whether a PCAP was already processed

- is_csv_processed(path)
  - checks whether a CSV was already processed

- queue_alert(payload)
  - saves failed alerts so they can be retried later

- get_queued_alerts()
  - returns the waiting alerts

- remove_alert(event_id)
  - removes an alert after it has succeeded

Why it is important:
This prevents the agent from reprocessing the same files over and over after a restart.

---

### config.json

Purpose:
This is the main configuration file.

What it contains:
- the network interface to capture from
- the PCAP output directory
- the CSV output directory
- the processed directory
- the CICFlowMeter command
- the model directory
- the alert endpoint URL
- timeout values
- dangerous labels
- confidence threshold
- logging settings

Why it is important:
You should change this file first when moving the project to another machine or environment.

---

### requirements.txt

Purpose:
This lists the Python packages the project needs.

The main ones are:
- requests
- pandas
- scikit-learn
- numpy
- fastapi
- uvicorn

Why it is important:
This makes installation simple and repeatable.

---

### test_receiver.py

Purpose:
This is a small local development receiver for testing alerts.

What it does:
- runs a small FastAPI web app
- exposes POST /alerts
- prints the received message
- stores the last received alerts in memory
- exposes GET /alerts

Why it is important:
This gives you a safe local endpoint to confirm that the agent can send a message before you connect it to a real application.

---

## 5. How the whole flow works in practice

Here is the real end-to-end flow:

1. The agent starts.
2. It loads the config file.
3. It loads the model artifacts.
4. It looks for PCAP files in the capture folder.
5. If a PCAP file is new, it runs CICFlowMeter on it.
6. CICFlowMeter creates a CSV file.
7. The Python agent reads the CSV file.
8. The rows are cleaned and prepared.
9. The model predicts whether each flow is benign or dangerous.
10. If the prediction is dangerous and the confidence is high enough, an alert is created.
11. The alert is sent to the test endpoint.
12. If sending fails, the alert is stored in the local SQLite queue.
13. On the next run, the agent retries those queued alerts.

That is the main lifecycle of the project.

---

## 6. The simple picture of the project

You can think of the project as four main stages:

### Stage 1: Capture
This is where network data is collected.

### Stage 2: Flow conversion
This is where PCAP data is turned into flow-based CSV data.

### Stage 3: Prediction
This is where the model looks at the features and decides whether a flow looks benign or dangerous.

### Stage 4: Alerting
This is where dangerous predictions are reported to an endpoint.

---

## 7. What each module is responsible for

Here is the short version:

- agent.py = boss / coordinator
- capture.py = packet capture
- cicflow_runner.py = PCAP to CSV conversion
- csv_processor.py = CSV cleanup and feature preparation
- predictor.py = model loading and prediction
- alert_sender.py = sending alerts
- state.py = remembering what was done
- config.json = settings
- test_receiver.py = local test endpoint

---

## 8. A beginner-friendly summary

If you want the absolute simplest explanation, it is this:

The project watches network traffic, turns it into flows, feeds those flows into a trained model, and then sends alerts when the model thinks something dangerous happened.

It is intentionally small and easy to understand. It is not trying to be a full enterprise security platform yet.

---

## 9. What the scripts folder is for

The scripts folder contains simple helper shell scripts.

### scripts/start_capture.sh
Purpose:
This script starts a tcpdump capture using a basic example command.

What it does:
- chooses the interface name passed in as an argument
- creates a PCAP output path
- starts tcpdump with a rotation pattern

Why it is useful:
It gives you a simple way to start capture without typing the full tcpdump command manually each time.

### scripts/run_once.sh
Purpose:
This script runs the agent one time.

What it does:
- changes to the project directory
- runs the agent with the --once option

Why it is useful:
It is a quick shortcut for testing the workflow without having to remember the full Python command.

---

## 10. Quick cheat sheet

Here is the fastest way to think about the project:

- agent.py = main runner
- capture.py = starts tcpdump
- cicflow_runner.py = converts PCAP to CSV
- csv_processor.py = cleans the CSV rows
- predictor.py = loads the model and predicts
- alert_sender.py = sends alerts
- state.py = remembers what already happened
- config.json = settings
- test_receiver.py = local test endpoint
- scripts/start_capture.sh = helper to start capture
- scripts/run_once.sh = helper to run one cycle

In one sentence:
The project captures traffic, converts it into flows, predicts whether it looks dangerous, and sends alerts when needed.

---

## 11. Important limitations

A few real-world limitations are worth remembering:

- This is not packet-by-packet blocking.
- A flow may only be available after it closes or times out.
- CICFlowMeter output must match the training feature definitions.
- Different CICFlowMeter versions may produce different columns.
- A model trained on a public dataset may not generalize perfectly to real traffic.
- The system reports predictions; it does not automatically block traffic.

---

## 12. Final takeaway

The project is a compact, understandable example of an intrusion-detection-style pipeline.

The important idea is:

Capture traffic -> convert to flows -> classify -> send alerts.

That is the whole project in one sentence.
