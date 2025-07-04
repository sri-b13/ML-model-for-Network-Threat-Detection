#classification model 

import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import re
from urllib.parse import urlparse


#Loading the dataset downloaded in the folder 
file_path = 'malicious_phish.csv'
df = pd.read_csv(file_path) #reading the file path for the dataset

print(f"Dataset loaded successfully")
#tabulating the data
print(f"Dataset shape: {df.shape}")
print(f"Columns: {df.columns.tolist()}")
print(f"\nClass distribution:")
print(df['type'].value_counts())

#Feature engineering for URLs performedd
def extract_url_features(url):
    """Extract features from URL"""
    features = {}
    
    #url length
    features['url_length'] = len(url)
    
    #no of dts
    features['num_dots'] = url.count('.')
    
    #hyphen no.
    features['num_hyphens'] = url.count('-')
    
    #underscores count
    features['num_underscores'] = url.count('_')
    
    #slashes count
    features['num_slashes'] = url.count('/')
    
    #no. of digits
    features['num_digits'] = sum(c.isdigit() for c in url)
    
    # Has IP address
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    features['has_ip'] = int(bool(re.search(ip_pattern, url)))
    
    #finding the number of path segments
    try:
        parsed_url = urlparse(url)
        features['url_depth'] = len([x for x in parsed_url.path.split('/') if x])
        features['domain_length'] = len(parsed_url.netloc) if parsed_url.netloc else 0
    except:
        features['url_depth'] = 0
        features['domain_length'] = 0
    
    #threat keywords that arise suspicion is allocated to a varaiable for easy detection
    suspicious_words = ['secure', 'account', 'update', 'verify', 'login', 'bank', 'paypal']
    features['suspicious_word_count'] = sum(word in url.lower() for word in suspicious_words)
    
    return features

#feature extraction
print("\nExtracting URL features...")
url_features = []
for url in df['url']:
    url_features.append(extract_url_features(str(url)))
feature_df = pd.DataFrame(url_features)

#variable allocation
X = feature_df
y = df['type']
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

print(f"\nFeatures extracted: {X.columns.tolist()}")
print(f"Feature matrix shape: {X.shape}")

#making training and testing variables 
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.3, random_state=42, stratify=y_encoded)

print(f"\nTraining set shape: {X_train.shape}")
print(f"Test set shape: {X_test.shape}")

#create a rndmfrst model
clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)

print("\nTraining the Random Forest model")
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)
y_pred_proba = clf.predict_proba(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\nModel Accuracy: {accuracy:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

cm = confusion_matrix(y_test, y_pred)
print("\nConfusion Matrix:")
print(cm)

if not os.path.exists('models'):
    os.makedirs('models')

joblib.dump(clf, 'models/phishing_classifier_model.pkl')
joblib.dump(label_encoder, 'models/label_encoder.pkl')
print("\nModel and label encoder saved successfully!")

#classiying important features 
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': clf.feature_importances_
}).sort_values('importance', ascending=False)

print("\nTop 10 Most Important Features:")
print(feature_importance.head(10))

#plot the figures
plt.figure(figsize=(15, 12))

#class distribution
plt.subplot(2, 3, 1)
class_counts = df['type'].value_counts()
plt.pie(class_counts.values, labels=class_counts.index, autopct='%1.1f%%', startangle=90)
plt.title('Original Dataset Class Distribution')

#prediction distribution
plt.subplot(2, 3, 2)
pred_labels = label_encoder.inverse_transform(y_pred)
pred_counts = pd.Series(pred_labels).value_counts()
plt.pie(pred_counts.values, labels=pred_counts.index, autopct='%1.1f%%', startangle=90)
plt.title('Prediction Distribution')

#Creating a confusion matrix heatmap for observing the data
plt.subplot(2, 3, 3)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=label_encoder.classes_, 
            yticklabels=label_encoder.classes_)
plt.title('Confusion Matrix')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')

plt.subplot(2, 3, 4)
top_features = feature_importance.head(8)
plt.barh(range(len(top_features)), top_features['importance'])
plt.yticks(range(len(top_features)), top_features['feature'])
plt.xlabel('Importance')
plt.title('Top 8 Feature Importance')
plt.gca().invert_yaxis()

plt.subplot(2, 3, 5)
for class_name in df['type'].unique():
    class_data = df[df['type'] == class_name]
    url_lengths = [len(str(url)) for url in class_data['url']]
    plt.hist(url_lengths, alpha=0.7, label=class_name, bins=30)
plt.xlabel('URL Length')
plt.ylabel('Frequency')
plt.title('URL Length Distribution by Class')
plt.legend()

#perf matrices
plt.subplot(2, 3, 6)
from sklearn.metrics import precision_recall_fscore_support
precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average=None)
metrics_df = pd.DataFrame({
    'Precision': precision,
    'Recall': recall,
    'F1-Score': f1
}, index=label_encoder.classes_)

metrics_df.plot(kind='bar', ax=plt.gca())
plt.title('Performance Metrics by Class')
plt.ylabel('Score')
plt.xticks(rotation=45)
plt.legend()

plt.tight_layout()
plt.savefig('phishing_classification_analysis.png', dpi=300, bbox_inches='tight')
plt.show()

print(f"\nAnalysing complete;saved to'phishing_classification_analysis.png'")
#creating a picture for the analysis
