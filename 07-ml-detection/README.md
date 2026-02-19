# ml-based intrusion detection

machine learning layer for network intrusion detection, complementing signature-based methods.

## tools

### train_model.py
trains random forest and gradient boosting classifiers on labelled network traffic data. handles preprocessing (missing values, encoding, scaling), evaluates with standard metrics, and saves the best model.

```bash
python3 train_model.py data/sample_benign.csv data/sample_attack.csv ./output
```

### predict.py
loads a trained model and classifies network flows as attack or benign.

```bash
# predict from csv
python3 predict.py output/model.pkl test_data.csv

# predict a single flow
python3 predict.py output/model.pkl --flow duration=0.5 protocol=tcp src_bytes=1024 dst_bytes=500 flag=SF service=http count=5 srv_count=3
```

### compare_detection.py
compares ml detection against suricata signature-based detection on the same traffic, generating charts and a detailed report.

```bash
python3 compare_detection.py /var/log/suricata/eve.json predictions.json labelled_data.csv ./comparison
```

### generate_features.py
extracts flow-level features from pcap files, outputting csv compatible with the trained model.

```bash
python3 generate_features.py capture.pcap features.csv
```

### generate_sample_data.py
creates sample benign and attack datasets for training and testing.

```bash
python3 generate_sample_data.py
```

## data format

features used by the model:

| feature | description |
|---------|-------------|
| duration | connection length in seconds |
| protocol | tcp, udp, or other |
| src_bytes | bytes from source to destination |
| dst_bytes | bytes from destination to source |
| flag | connection state (SF, S0, REJ, RSTO, OTH) |
| service | destination service (http, ssh, dns, etc) |
| count | connections from same source in window |
| srv_count | connections to same service in window |
| label | benign or attack (training data only) |

## setup

```bash
pip install -r requirements.txt
python3 generate_sample_data.py
python3 train_model.py data/sample_benign.csv data/sample_attack.csv ./output
```
