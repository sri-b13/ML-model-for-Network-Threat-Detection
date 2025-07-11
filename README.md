# ML-model-for-Network-Threat-Detection

## Intel 
Made a proejct for a problem statement provided by Intel Incorporation under their Industrial Training Program


Automated network traffic analysis using AI/ML to enable real-time detection and classification, improved threat identification, reduced false alerts, scalable performance, and privacy-preserving encrypted traffic analysis.
With the rapid expansion of data volume, encrypted services, and advanced cyberattacks, monitoring and securing network traffic has become increasingly complex. Traditional methods like signature-based detection and deep packet inspection (DPI) struggle to keep up—especially with encrypted data streams. Manual processes for traffic classification are no longer viable, often resulting in delayed responses and potential security breaches.

Artificial Intelligence offers a robust alternative, enabling systems to dynamically recognize traffic behaviors, flag anomalies, and secure networks proactively—without requiring human intervention.

## Description

- **Smart Traffic Detection**  
  AI models dynamically track and identify network data streams, ensuring timely traffic classification.

- **Stronger Cyber Defense**  
  Enhanced detection of suspicious behaviors, malware, and complex attack patterns—even within encrypted channels.

- **Minimized Detection Errors**  
  Lower false alarm rates, improving trust and precision in identifying real threats.

- **Efficient at Scale**  
  Capable of managing large-scale network environments with minimal computational overhead.

- **Secure Yet Private**  
  Traffic analysis without compromising user privacy—no decryption required.

---

## Project Components

- **Behavior-Based Classification Engine**  
  An AI-driven module to categorize network traffic types and application-level identities in real-time.

- **Anomaly Detection & Threat Monitoring System**  
  A learning-based framework that continuously watches for unusual patterns and detects potential intrusions.


### **Understanding the Problem Statement**

The problem revolves around **classifying network traffic and identifying threats/anomalies**, even when:

- Traffic is encrypted 
- Application behaviors overlaps  
- Manual intervention is too slow
  

Research indicated that **machine learning and AI models** can be trained to identify traffic patterns, detect suspicious behavior, and improve network security — all based on **metadata (headers, timings, etc.)** without needing payload access.

To build an AI system that,
- Classifies encrypted traffic **without decryption**
- Detects anomalies and malicious behavior
- Operates in **real time** 
- Maintains **high accuracy**, **low latency**, and **privacy compliance**

Research papers studied
[ISCX VPN-nonVPN paper](https://ieeexplore.ieee.org/document/7095802)
[Deep Packet paper (University of Brescia)](https://arxiv.org/abs/1709.02656)

### **Feature Extraction**
Extract features like:

|Feature Category|Examples|
|---|---|
|Basic|Duration, Protocol, Flow Bytes/s, Packets/s|
|Time-based|Avg Packet Gap, Idle time, Active time|
|Size-based|Min/Max Packet Size, Std Dev, Flow IAT|
|Directional|Ratio of incoming/outgoing traffic|

### **Evaluation Matrices**

|Task|Metrics|
|---|---|
|Classification|Accuracy, F1-score, Precision, Recall|
|Anomaly Detection|AUC, ROC, True Positive Rate, False Positive Rate|

### **Visualization and Dashboard**
Using **Streamlit** to,
    - Show real-time traffic type distribution
    - Log alerts for anomalies or attacks
    - Performance metrics for the model

## Conclusion
This project details a holistic, AI-driven framework for network security that automates the detection and classification of network traffic and threats, particularly focusing on web application attacks like SQLi and XSS. The system is designed for high accuracy and real-time performance, leveraging a hybrid of rule-based, machine learning, and deep learning techniques. It provides practical insights into model selection, feature engineering, performance benchmarking, and deployment in real-world environments such as WAFs1. This aligns with modern network security needs for scalability, adaptability, and privacy-preserving analysis in the face of increasingly sophisticated and encrypted cyber threats.

    

