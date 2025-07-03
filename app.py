import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import joblib
import os
import sys
from datetime import datetime
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import warnings
warnings.filterwarnings('ignore')

st.set_page_config(
    page_title="Network Security ML Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .section-header {
        font-size: 1.5rem;
        color: #ff7f0e;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .alert-box {
        background-color: #ffebee;
        border-left: 5px solid #f44336;
        padding: 1rem;
        margin: 1rem 0;
    }
    .success-box {
        background-color: #e8f5e8;
        border-left: 5px solid #4caf50;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

class NetworkSecurityDashboard:
    def __init__(self):
        self.phishing_data = None
        self.web_attacks_data = None
        self.models = {}
        
    def load_data(self):
        """Load the datasets"""
        try:
            #loading the data 
            base_paths = [
                r"C:\Users\srila\network-security-ml\data",
                r"C:\Users\srila\OneDrive\Desktop\Personal\Intel Model"
            ]
            
            for base_path in base_paths:
                phishing_path = os.path.join(base_path, "malicious_phish.csv")
                attacks_path = os.path.join(base_path, "multi_class_web_attacks.csv")
                
                if os.path.exists(phishing_path) and os.path.exists(attacks_path):
                    self.phishing_data = pd.read_csv(phishing_path)
                    self.web_attacks_data = pd.read_csv(attacks_path)
                    st.success(f"✅ Data loaded successfully from {base_path}")
                    return True
            
            st.error("Could not find data files. Please check the file paths.")
            return False
            
        except Exception as e:
            st.error(f"❌ Error loading data: {str(e)}")
            return False
    
    def extract_url_features(self, url):
        """Extract features from URL for phishing detection"""
        features = {}
        url = str(url)
        
        #url features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        #ip
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        features['has_ip'] = int(bool(re.search(ip_pattern, url)))
        
    
        try:
            parsed_url = urlparse(url)
            features['url_depth'] = len([x for x in parsed_url.path.split('/') if x])
            features['domain_length'] = len(parsed_url.netloc) if parsed_url.netloc else 0
        except:
            features['url_depth'] = 0
            features['domain_length'] = 0
        
    
        suspicious_words = ['secure', 'account', 'update', 'verify', 'login', 'bank', 'paypal']
        features['suspicious_word_count'] = sum(word in url.lower() for word in suspicious_words)
        
        return features
    
    def extract_attack_features(self, url):
        """Extract features from URL for attack detection"""
        features = {}
        url = str(url)
        
       #url chrac
        features['url_length'] = len(url)
        features['num_params'] = url.count('&') + url.count('?')
        features['num_dots'] = url.count('.')
        features['num_slashes'] = url.count('/')
        features['num_equals'] = url.count('=')
        features['num_percent'] = url.count('%')
        features['num_semicolon'] = url.count(';')
        features['num_quotes'] = url.count("'") + url.count('"')
        
      
        sql_keywords = ['union', 'select', 'drop', 'insert', 'delete', 'update', 'or', 'and', '--', ';']
        features['sql_keyword_count'] = sum(keyword in url.lower() for keyword in sql_keywords)
        xss_keywords = ['script', 'alert', 'onload', 'onerror', 'onmouseover', 'javascript']
        features['xss_keyword_count'] = sum(keyword in url.lower() for keyword in xss_keywords)
        features['path_traversal_count'] = url.count('../') + url.count('..\\') + url.count('%2e%2e')
        cmd_keywords = ['cat', 'ls', 'dir', 'ping', 'whoami', 'netstat', 'cmd']
        features['cmd_keyword_count'] = sum(keyword in url.lower() for keyword in cmd_keywords)
        features['special_char_count'] = sum(url.count(char) for char in ['<', '>', '{', '}', '|', '`'])
        features['encoded_char_count'] = url.count('%')
        
        return features
    
    def train_phishing_model(self):
        """Train phishing detection model"""
        if self.phishing_data is None:
            return None
        
        features_list = []
        for url in self.phishing_data['url']:
            features_list.append(self.extract_url_features(url))
        
        X = pd.DataFrame(features_list)
        y = self.phishing_data['type']
        
       
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y)
        
       #train_test model
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.3, random_state=42, stratify=y_encoded
        )
        
        #training the model
        model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
        model.fit(X_train, y_train)
        
       #predicting the model
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        return {
            'model': model,
            'label_encoder': label_encoder,
            'X_test': X_test,
            'y_test': y_test,
            'y_pred': y_pred,
            'accuracy': accuracy,
            'feature_names': X.columns.tolist()
        }
    
    def train_threat_detection_model(self):
        """Train threat detection model"""
        if self.web_attacks_data is None:
            return None
        
        
        features_list = []
        for url in self.web_attacks_data['url']:
            features_list.append(self.extract_attack_features(url))
        
        X = pd.DataFrame(features_list)
        
        #assign bening = 0 and malicious = 1
        y = (self.web_attacks_data['label'] != 'benign').astype(int)
        
        #features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        #trrain
        contamination = min(0.5, max(0.01, y.mean()))
        iso_forest = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
        anomaly_predictions = iso_forest.fit_predict(X_scaled)
        y_pred = (anomaly_predictions == -1).astype(int)
        
        accuracy = accuracy_score(y, y_pred)
        
        return {
            'model': iso_forest,
            'scaler': scaler,
            'X': X,
            'y_true': y,
            'y_pred': y_pred,
            'accuracy': accuracy,
            'feature_names': X.columns.tolist()
        }

def main():
    st.markdown('<h1 class="main-header">🛡️ Network Security ML Dashboard</h1>', unsafe_allow_html=True)
    
    
    dashboard = NetworkSecurityDashboard()
    st.sidebar.title("Dashboard Controls")
    if st.sidebar.button("📊 Load Data", type="primary"):
        with st.spinner("Loading datasets..."):
            data_loaded = dashboard.load_data()
        
        if data_loaded:
            st.sidebar.success("Data loaded successfully")
        else:
            st.sidebar.error("Failed to load data")
            return
    
    # Check if data is loaded
    if dashboard.phishing_data is None or dashboard.web_attacks_data is None:
        st.warning("Please load the data first using the sidebar.")
        return
    
    # Navigation
    page = st.sidebar.selectbox("📋 Select Analysis", [
        "📈 Dashboard Overview",
        "🎯 Phishing Detection",
        "⚡ Threat Detection",
        "🔍 URL Analysis Tool",
        "📊 Data Insights"
    ])
    
    if page == "📈 Dashboard Overview":
        show_dashboard_overview(dashboard)
    elif page == "🎯 Phishing Detection":
        show_phishing_analysis(dashboard)
    elif page == "⚡ Threat Detection":
        show_threat_analysis(dashboard)
    elif page == "🔍 URL Analysis Tool":
        show_url_analysis_tool(dashboard)
    elif page == "📊 Data Insights":
        show_data_insights(dashboard)

def show_dashboard_overview(dashboard):
    """Show main dashboard overview"""
    st.markdown('<h2 class="section-header">📈 Dashboard Overview</h2>', unsafe_allow_html=True)
    
   
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="📊 Phishing URLs",
            value=f"{len(dashboard.phishing_data):,}",
            delta=f"{dashboard.phishing_data['type'].value_counts().get('phishing', 0)} phishing"
        )
    
    with col2:
        st.metric(
            label="⚡ Web Attacks",
            value=f"{len(dashboard.web_attacks_data):,}",
            delta=f"{(dashboard.web_attacks_data['label'] != 'benign').sum()} attacks"
        )
    
    with col3:
        phishing_rate = (dashboard.phishing_data['type'] == 'phishing').mean() * 100
        st.metric(
            label="🎯 Phishing Rate",
            value=f"{phishing_rate:.1f}%",
            delta=f"Detection accuracy target: 95%"
        )
    
    with col4:
        attack_rate = (dashboard.web_attacks_data['label'] != 'benign').mean() * 100
        st.metric(
            label="🚨 Attack Rate",
            value=f"{attack_rate:.1f}%",
            delta=f"Threat level: {'High' if attack_rate > 50 else 'Medium'}"
        )
    
    #charts and graphs
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Phishing Data Distribution")
        phishing_counts = dashboard.phishing_data['type'].value_counts()
        fig_phishing = px.pie(
            values=phishing_counts.values,
            names=phishing_counts.index,
            title="Phishing vs Benign vs Defacement vs Malware",
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        fig_phishing.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig_phishing, use_container_width=True)
    
    with col2:
        st.subheader("⚡ Web Attack Types Distribution")
        attack_counts = dashboard.web_attacks_data['label'].value_counts()
        fig_attacks = px.pie(
            values=attack_counts.values,
            names=attack_counts.index,
            title="Attack Types Distribution",
            color_discrete_sequence=px.colors.qualitative.Pastel
        )
        fig_attacks.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig_attacks, use_container_width=True)
    
    
    st.subheader("📊 Real-time Security Monitoring")
    
    
    recent_data = dashboard.web_attacks_data.sample(50).copy()
    recent_data['timestamp'] = pd.date_range(start='2024-01-01', periods=50, freq='1H')
    recent_data['severity'] = np.random.choice(['Low', 'Medium', 'High'], 50, p=[0.5, 0.3, 0.2])
    
    fig_timeline = px.scatter(
        recent_data,
        x='timestamp',
        y='label',
        color='severity',
        size_max=15,
        title="Recent Security Events Timeline",
        color_discrete_map={'Low': 'green', 'Medium': 'orange', 'High': 'red'}
    )
    fig_timeline.update_layout(height=400)
    st.plotly_chart(fig_timeline, use_container_width=True)

def show_phishing_analysis(dashboard):
    """Show phishing detection analysis"""
    st.markdown('<h2 class="section-header">🎯 Phishing Detection Analysis</h2>', unsafe_allow_html=True)
    
    if st.button("🔄 Train Phishing Detection Model", type="primary"):
        with st.spinner("Training phishing detection model..."):
            results = dashboard.train_phishing_model()
        
        if results:
            st.success(f"✅ Model trained successfully! Accuracy: {results['accuracy']:.3f}")
            dashboard.models['phishing'] = results
            
            #conf mat
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("📊 Confusion Matrix")
                cm = confusion_matrix(results['y_test'], results['y_pred'])
                fig_cm = px.imshow(
                    cm,
                    text_auto=True,
                    aspect="auto",
                    title="Confusion Matrix",
                    color_continuous_scale="Blues"
                )
                fig_cm.update_xaxes(title="Predicted")
                fig_cm.update_yaxes(title="Actual")
                st.plotly_chart(fig_cm, use_container_width=True)
            
            with col2:
                st.subheader("🔍 Feature Importance")
                feature_importance = pd.DataFrame({
                    'feature': results['feature_names'],
                    'importance': results['model'].feature_importances_
                }).sort_values('importance', ascending=True).tail(10)
                
                fig_importance = px.bar(
                    feature_importance,
                    x='importance',
                    y='feature',
                    orientation='h',
                    title="Top 10 Feature Importance",
                    color='importance',
                    color_continuous_scale="viridis"
                )
                st.plotly_chart(fig_importance, use_container_width=True)
            
            #classification report
            st.subheader("📋 Classification Report")
            report = classification_report(
                results['y_test'], 
                results['y_pred'], 
                target_names=results['label_encoder'].classes_,
                output_dict=True
            )
            report_df = pd.DataFrame(report).transpose()
            st.dataframe(report_df.round(3), use_container_width=True)
        else:
            st.error("Failed to train model")
    
    #url l analysis
    st.subheader("📏 URL Length Analysis by Type")
    url_lengths = dashboard.phishing_data.copy()
    url_lengths['url_length'] = url_lengths['url'].str.len()
    
    fig_length = px.box(
        url_lengths,
        x='type',
        y='url_length',
        title="URL Length Distribution by Type",
        color='type'
    )
    fig_length.update_layout(height=400)
    st.plotly_chart(fig_length, use_container_width=True)

def show_threat_analysis(dashboard):
    """Show threat detection analysis"""
    st.markdown('<h2 class="section-header">⚡ Threat Detection Analysis</h2>', unsafe_allow_html=True)
    
    if st.button("🔄 Train Threat Detection Model", type="primary"):
        with st.spinner("Training threat detection model..."):
            results = dashboard.train_threat_detection_model()
        
        if results:
            st.success(f"✅ Model trained successfully! Accuracy: {results['accuracy']:.3f}")
            dashboard.models['threat'] = results
            
            #analysis
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("🎯 Threat Detection Performance")
                cm = confusion_matrix(results['y_true'], results['y_pred'])
                fig_cm = px.imshow(
                    cm,
                    text_auto=True,
                    aspect="auto",
                    title="Threat Detection Confusion Matrix",
                    color_continuous_scale="Reds",
                    labels=dict(x="Predicted", y="Actual")
                )
                st.plotly_chart(fig_cm, use_container_width=True)
            
            with col2:
                st.subheader("📊 Feature Analysis")
                feature_stats = results['X'].describe()
                st.dataframe(feature_stats.round(2), use_container_width=True)
            
            
            st.subheader("🚨 Attack Type Breakdown")
            attack_breakdown = dashboard.web_attacks_data['label'].value_counts()
            
            fig_breakdown = px.bar(
                x=attack_breakdown.index,
                y=attack_breakdown.values,
                title="Attack Types Frequency",
                color=attack_breakdown.values,
                color_continuous_scale="Reds"
            )
            fig_breakdown.update_xaxes(title="Attack Type")
            fig_breakdown.update_yaxes(title="Count")
            st.plotly_chart(fig_breakdown, use_container_width=True)
        else:
            st.error("❌ Failed to train model")

def show_url_analysis_tool(dashboard):
    """Show URL analysis tool"""
    st.markdown('<h2 class="section-header">🔍 URL Analysis Tool</h2>', unsafe_allow_html=True)
    
    st.write("Enter a URL to analyze for potential threats:")
    
    url_input = st.text_input("🌐 Enter URL:", placeholder="https://example.com/path")
    
    if st.button("🔍 Analyze URL", type="primary") and url_input:
        #feature extraction
        phishing_features = dashboard.extract_url_features(url_input)
        attack_features = dashboard.extract_attack_features(url_input)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🎯 Phishing Analysis")
            phishing_df = pd.DataFrame([phishing_features])
            st.dataframe(phishing_df.T, column_config={"0": "Value"})
            
            #heuristis risk score
            risk_score = (
                phishing_features['suspicious_word_count'] * 20 +
                phishing_features['has_ip'] * 30 +
                min(phishing_features['url_length'] / 100, 1) * 25 +
                phishing_features['num_dots'] * 5
            )
            
            if risk_score > 50:
                st.markdown('<div class="alert-box">🚨 <b>HIGH RISK:</b> This URL shows signs of phishing!</div>', unsafe_allow_html=True)
            elif risk_score > 25:
                st.markdown('<div style="background-color: #fff3cd; border-left: 5px solid #ffc107; padding: 1rem;">⚠️ <b>MEDIUM RISK:</b> Be cautious with this URL.</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="success-box">✅ <b>LOW RISK:</b> URL appears to be safe.</div>', unsafe_allow_html=True)
        
        with col2:
            st.subheader("⚡ Attack Analysis")
            attack_df = pd.DataFrame([attack_features])
            st.dataframe(attack_df.T, column_config={"0": "Value"})
            
            #adding indicators to find attacks
            attack_indicators = []
            if attack_features['sql_keyword_count'] > 0:
                attack_indicators.append("SQL Injection")
            if attack_features['xss_keyword_count'] > 0:
                attack_indicators.append("XSS")
            if attack_features['path_traversal_count'] > 0:
                attack_indicators.append("Path Traversal")
            if attack_features['cmd_keyword_count'] > 0:
                attack_indicators.append("Command Injection")
            
            if attack_indicators:
                st.markdown(f'<div class="alert-box">🚨 <b>ATTACK DETECTED:</b> {", ".join(attack_indicators)}</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="success-box">✅ <b>NO ATTACKS DETECTED:</b> URL appears clean.</div>', unsafe_allow_html=True)

def show_data_insights(dashboard):
    """Show data insights and statistics"""
    st.markdown('<h2 class="section-header">Data Insights</h2>', unsafe_allow_html=True)
    
    #data comprehensice summary to be displayed
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Phishing Dataset Summary")
        st.write(f"**Total Records:** {len(dashboard.phishing_data):,}")
        st.write(f"**Features:** URL, Type")
        st.write("**Classes:**")
        for class_name, count in dashboard.phishing_data['type'].value_counts().items():
            percentage = (count / len(dashboard.phishing_data)) * 100
            st.write(f"  - {class_name}: {count:,} ({percentage:.1f}%)")
    
    with col2:
        st.subheader("⚡ Web Attacks Dataset Summary")
        st.write(f"**Total Records:** {len(dashboard.web_attacks_data):,}")
        st.write(f"**Features:** URL, Label")
        st.write("**Attack Types:**")
        for attack_type, count in dashboard.web_attacks_data['label'].value_counts().items():
            percentage = (count / len(dashboard.web_attacks_data)) * 100
            st.write(f"  - {attack_type}: {count:,} ({percentage:.1f}%)")
    
    #url length distribution
    st.subheader("📏 URL Length Distribution Comparison")
    
    phishing_lengths = dashboard.phishing_data['url'].str.len()
    attack_lengths = dashboard.web_attacks_data['url'].str.len()
    
    fig_lengths = make_subplots(
        rows=1, cols=2,
        subplot_titles=("Phishing Dataset", "Web Attacks Dataset"),
        specs=[[{"secondary_y": False}, {"secondary_y": False}]]
    )
    fig_lengths.add_trace(
        go.Histogram(x=phishing_lengths, name="Phishing URLs", opacity=0.7),
        row=1, col=1
    )
    fig_lengths.add_trace(
        go.Histogram(x=attack_lengths, name="Attack URLs", opacity=0.7),
        row=1, col=2
    )
    fig_lengths.update_layout(
        title="URL Length Distribution Comparison",
        height=400,
        showlegend=False
    )
    fig_lengths.update_xaxes(title_text="URL Length")
    fig_lengths.update_yaxes(title_text="Frequency")
    
    st.plotly_chart(fig_lengths, use_container_width=True)
    
    #preview data
    st.subheader("Sample Data Preview")
    
    tab1, tab2 = st.tabs(["🎯 Phishing Data", "⚡ Attack Data"])
    
    with tab1:
        st.dataframe(dashboard.phishing_data.head(10), use_container_width=True)
    
    with tab2:
        st.dataframe(dashboard.web_attacks_data.head(10), use_container_width=True)

if __name__ == "__main__":
    main()
