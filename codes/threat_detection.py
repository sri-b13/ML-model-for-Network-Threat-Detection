# model for threat deteciton (python) 

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
import datetime
import os

#loading the dataset
file_path = 'multi_class_web_attacks.csv'
df = pd.read_csv(file_path)

print(f"Dataset loaded successfully")
print(f"Dataset shape: {df.shape}")
print(f"Columns: {df.columns.tolist()}")
print(f"\nAttack type distribution:")
print(df['label'].value_counts())

#feature engineering for detection
def extract_attack_features(url):
    """Extract features from URL for attack detection"""
    features = {}
    
    #url descriptions 
    features['url_length'] = len(url)
    features['num_params'] = url.count('&') + url.count('?')
    features['num_dots'] = url.count('.')
    features['num_slashes'] = url.count('/')
    features['num_equals'] = url.count('=')
    features['num_percent'] = url.count('%')
    features['num_semicolon'] = url.count(';')
    features['num_quotes'] = url.count("'") + url.count('"')
    
    #indications for SQLi
    sql_keywords = ['union', 'select', 'drop', 'insert', 'delete', 'update', 'or', 'and', '--', ';']
    features['sql_keyword_count'] = sum(keyword in url.lower() for keyword in sql_keywords)
    
    #XSS
    xss_keywords = ['script', 'alert', 'onload', 'onerror', 'onmouseover', 'javascript']
    features['xss_keyword_count'] = sum(keyword in url.lower() for keyword in xss_keywords)
    
    features['path_traversal_count'] = url.count('../') + url.count('..\\') + url.count('%2e%2e')
    
    #cmdi
    cmd_keywords = ['cat', 'ls', 'dir', 'ping', 'whoami', 'netstat', 'cmd']
    features['cmd_keyword_count'] = sum(keyword in url.lower() for keyword in cmd_keywords)
    
    #psecial char
    features['special_char_count'] = sum(url.count(char) for char in ['<', '>', '{', '}', '|', '`'])
    features['encoded_char_count'] = url.count('%')
    
    return features

#feature extraction from urls 
print("\nExtracting attack detection features...")
attack_features = []
for url in df['url']:
    attack_features.append(extract_attack_features(str(url)))

feature_df = pd.DataFrame(attack_features)

feature_df['timestamp'] = pd.date_range(start='2024-01-01', periods=len(df), freq='1min')

df['is_attack'] = (df['label'] != 'benign').astype(int)
analysis_df = pd.concat([feature_df, df[['label', 'is_attack']]], axis=1)
print(f"\nAnalysis dataframe shape: {analysis_df.shape}")
print(f"Features: {feature_df.columns.tolist()}")

feature_cols = [col for col in feature_df.columns if col not in ['timestamp']]
X = analysis_df[feature_cols]
print(f"\nUsing features for anomaly detection: {feature_cols}")

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

#finding teh attack rate at which the contamination is taking place
attack_rate = analysis_df['is_attack'].mean()
contamination = min(0.5, max(0.01, attack_rate))
print(f"Actual attack rate: {attack_rate:.3f}")
print(f"Using contamination parameter: {contamination:.3f}")


iso_forest = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
analysis_df['anomaly'] = iso_forest.fit_predict(X_scaled)
analysis_df['is_anomaly'] = analysis_df['anomaly'].apply(lambda x: 1 if x == -1 else 0)

from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

#metrics
accuracy = accuracy_score(analysis_df['is_attack'], analysis_df['is_anomaly'])
print(f"\nThreat Detection Performance:")
print(f"Accuracy: {accuracy:.4f}")
print("\nClassification Report:")
print(classification_report(analysis_df['is_attack'], analysis_df['is_anomaly'], 
                          target_names=['Benign', 'Attack']))

#log anomalies
log_dir = '../logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

anomalies = analysis_df[analysis_df['is_anomaly'] == 1]
log_file = os.path.join(log_dir, 'web_attack_alerts.log')

with open(log_file, 'w') as f:
    f.write(f"Web Attack Detection Log - Generated on {datetime.datetime.now()}\n")
    f.write("="*60 + "\n\n")
    
    for idx, row in anomalies.iterrows():
        original_url = df.iloc[idx]['url']
        actual_label = df.iloc[idx]['label']
        f.write(f"ALERT: Potential attack detected at {row['timestamp']}\n")
        f.write(f"  - URL: {original_url}\n")
        f.write(f"  - Actual Label: {actual_label}\n")
        f.write(f"  - URL Length: {row['url_length']}\n")
        f.write(f"  - SQL Keywords: {row['sql_keyword_count']}\n")
        f.write(f"  - XSS Keywords: {row['xss_keyword_count']}\n")
        f.write(f"  - Path Traversal: {row['path_traversal_count']}\n")
        f.write(f"  - CMD Keywords: {row['cmd_keyword_count']}\n")
        f.write(f"  - Special Chars: {row['special_char_count']}\n")
        f.write("-" * 40 + "\n")

print(f"\nThreat detection completed!")
print(f"Total samples: {len(analysis_df)}")
print(f"Anomalies detected: {len(anomalies)}")
print(f"Anomaly rate: {len(anomalies)/len(analysis_df)*100:.2f}%")
print(f"Alerts logged to: {log_file}")

#plots and firgures
plt.figure(figsize=(15, 10))

#fig 1 = Attack type distribution
plt.subplot(2, 3, 1)
attack_counts = df['label'].value_counts()
plt.bar(attack_counts.index, attack_counts.values)
plt.xlabel('Attack Type')
plt.ylabel('Count')
plt.title('Attack Type Distribution')
plt.xticks(rotation=45)

#fig 2 = Feature distribution - url Length
plt.subplot(2, 3, 2)
normal = analysis_df[analysis_df['is_anomaly'] == 0]
anomaly = analysis_df[analysis_df['is_anomaly'] == 1]
plt.hist(normal['url_length'], bins=50, alpha=0.7, label='Normal', color='blue', density=True)
plt.hist(anomaly['url_length'], bins=30, alpha=0.7, label='Anomaly', color='red', density=True)
plt.xlabel('URL Length')
plt.ylabel('Density')
plt.title('URL Length Distribution')
plt.legend()

#fig 3 = (imp) SQL & XSS 
plt.subplot(2, 3, 3)
plt.scatter(analysis_df['sql_keyword_count'], analysis_df['xss_keyword_count'], 
           c=analysis_df['is_anomaly'], cmap='coolwarm', alpha=0.6)
plt.xlabel('SQL Keyword Count')
plt.ylabel('XSS Keyword Count')
plt.title('SQL vs XSS Keywords')
plt.colorbar(label='Anomaly (1) vs Normal (0)')

#fig4 = anomaly 
plt.subplot(2, 3, 4)
anomaly_scores = iso_forest.decision_function(X_scaled)
plt.hist(anomaly_scores[analysis_df['is_anomaly'] == 0], bins=50, alpha=0.7, label='Normal', color='blue', density=True)
plt.hist(anomaly_scores[analysis_df['is_anomaly'] == 1], bins=30, alpha=0.7, label='Anomaly', color='red', density=True)
plt.xlabel('Anomaly Score')
plt.ylabel('Density')
plt.title('Anomaly Score Distribution')
plt.legend()

#fig 5 = spl char
plt.subplot(2, 3, 5)
plt.hist(normal['special_char_count'], bins=20, alpha=0.7, label='Normal', color='blue', density=True)
plt.hist(anomaly['special_char_count'], bins=20, alpha=0.7, label='Anomaly', color='red', density=True)
plt.xlabel('Special Character Count')
plt.ylabel('Density')
plt.title('Special Characters Distribution')
plt.legend()

#fig6 = pie chart
plt.subplot(2, 3, 6)
detection_counts = analysis_df['is_anomaly'].value_counts()
labels = ['Normal', 'Anomaly']
colors = ['#66b3ff', '#ff9999']
plt.pie(detection_counts.values, labels=labels, autopct='%1.1f%%', 
        colors=colors, startangle=90)
plt.title('Threat Detection Results')

plt.tight_layout()
plt.savefig('../logs/threat_detection_analysis.png', dpi=300, bbox_inches='tight')
plt.show()

#model saving
import joblib
model_dir = '../models'
if not os.path.exists(model_dir):
    os.makedirs(model_dir)
    
joblib.dump(iso_forest, os.path.join(model_dir, 'threat_detection_model.pkl'))
joblib.dump(scaler, os.path.join(model_dir, 'scaler.pkl'))
print("\nModels saved successfully")
