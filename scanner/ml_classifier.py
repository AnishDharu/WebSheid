"""
Machine Learning Risk Classifier for Web Shield
Uses Logistic Regression to classify overall website risk.
"""

import numpy as np
import os
import pickle

try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    SK_AVAILABLE = True
except ImportError:
    SK_AVAILABLE = False

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ml_model.pkl')
SCALER_PATH = os.path.join(os.path.dirname(__file__), 'ml_scaler.pkl')


def extract_features(findings, raw_results):
    """
    Extract numerical features from scan findings for ML classification.
    Returns feature vector as numpy array.
    """
    # Count severities
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        sev = f.get('severity', 'info')
        if sev in severity_counts:
            severity_counts[sev] += 1

    # SSL Features
    ssl_raw = raw_results.get('ssl', {})
    has_ssl = 1 if ssl_raw.get('has_ssl', False) else 0
    cert_expiry_days = min(ssl_raw.get('cert_expiry_days', 365), 365)

    # Header features
    header_raw = raw_results.get('headers', {})
    missing_headers = header_raw.get('missing_headers_count', 7)

    # Port features
    port_raw = raw_results.get('ports', {})
    open_dangerous_ports = len([
        p for p in port_raw.get('open_ports', [])
        if p in [21, 23, 3306, 5432, 6379, 27017, 3389, 5900]
    ])

    # Cookie features
    cookie_raw = raw_results.get('cookies', {})
    cookie_count = cookie_raw.get('cookie_count', 0)

    # XSS features
    xss_raw = raw_results.get('xss', {})
    inline_scripts = xss_raw.get('inline_scripts_count', 0)

    # DNS features
    dns_raw = raw_results.get('dns', {})
    has_spf = 1 if dns_raw.get('has_spf', False) else 0

    # Directory exposure
    dir_raw = raw_results.get('subdomains', {})
    exposed_paths = len(dir_raw.get('exposed_paths', []))

    features = np.array([
        severity_counts['critical'],    # f0
        severity_counts['high'],        # f1
        severity_counts['medium'],      # f2
        severity_counts['low'],         # f3
        has_ssl,                        # f4
        cert_expiry_days,               # f5
        missing_headers,                # f6
        open_dangerous_ports,           # f7
        inline_scripts,                 # f8
        has_spf,                        # f9
        exposed_paths,                  # f10
        cookie_count,                   # f11
    ], dtype=float)

    return features


def compute_security_score(findings):
    """
    Compute a 0-100 security score based on findings.
    Starts at 100, deducted based on severity.
    """
    score = 100.0
    deductions = {
        'critical': 20,
        'high': 10,
        'medium': 5,
        'low': 2,
        'info': 0,
    }
    for f in findings:
        sev = f.get('severity', 'info')
        score -= deductions.get(sev, 0)

    return max(0, min(100, score))


def classify_risk(score, features=None):
    """
    Classify overall risk level using Logistic Regression model or rule-based fallback.
    """
    if SK_AVAILABLE and os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, 'rb') as f:
                model = pickle.load(f)
            with open(SCALER_PATH, 'rb') as f:
                scaler = pickle.load(f)
            if features is not None:
                scaled = scaler.transform(features.reshape(1, -1))
                prediction = model.predict(scaled)[0]
                return prediction
        except Exception:
            pass

    # Rule-based fallback when model not trained yet
    if score >= 80:
        return 'Low'
    elif score >= 60:
        return 'Medium'
    elif score >= 35:
        return 'High'
    else:
        return 'Critical'


def get_severity_summary(findings):
    """Return count of findings per severity level."""
    summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        sev = f.get('severity', 'info')
        if sev in summary:
            summary[sev] += 1
    return summary


def train_model():
    """
    Train the Logistic Regression model with synthetic data.
    In production, use real labeled scan data.
    """
    if not SK_AVAILABLE:
        return False

    # Generate synthetic training data
    # Features: [critical, high, medium, low, has_ssl, cert_days, missing_headers,
    #            dangerous_ports, inline_scripts, has_spf, exposed_paths, cookie_count]
    np.random.seed(42)
    n_samples = 1000

    X = []
    y = []

    labels = ['Low', 'Medium', 'High', 'Critical']
    for _ in range(n_samples):
        risk_class = np.random.choice(labels, p=[0.25, 0.30, 0.25, 0.20])
        if risk_class == 'Low':
            features = [
                np.random.randint(0, 1),    # critical
                np.random.randint(0, 2),    # high
                np.random.randint(0, 3),    # medium
                np.random.randint(0, 5),    # low
                1,                           # has_ssl
                np.random.randint(60, 365), # cert_days
                np.random.randint(0, 3),    # missing_headers
                0,                           # dangerous_ports
                np.random.randint(0, 3),    # inline_scripts
                1,                           # has_spf
                np.random.randint(0, 2),    # exposed_paths
                np.random.randint(0, 5),    # cookie_count
            ]
        elif risk_class == 'Medium':
            features = [
                np.random.randint(0, 2),
                np.random.randint(1, 4),
                np.random.randint(2, 6),
                np.random.randint(2, 7),
                np.random.randint(0, 2),
                np.random.randint(30, 200),
                np.random.randint(2, 5),
                np.random.randint(0, 2),
                np.random.randint(1, 5),
                np.random.randint(0, 2),
                np.random.randint(0, 3),
                np.random.randint(0, 8),
            ]
        elif risk_class == 'High':
            features = [
                np.random.randint(0, 3),
                np.random.randint(3, 7),
                np.random.randint(3, 8),
                np.random.randint(2, 8),
                np.random.randint(0, 2),
                np.random.randint(0, 100),
                np.random.randint(4, 7),
                np.random.randint(1, 3),
                np.random.randint(3, 8),
                0,
                np.random.randint(2, 5),
                np.random.randint(1, 10),
            ]
        else:  # Critical
            features = [
                np.random.randint(2, 6),
                np.random.randint(4, 10),
                np.random.randint(3, 10),
                np.random.randint(2, 8),
                0,
                np.random.randint(0, 30),
                np.random.randint(5, 7),
                np.random.randint(2, 5),
                np.random.randint(5, 12),
                0,
                np.random.randint(3, 7),
                np.random.randint(3, 15),
            ]
        X.append(features)
        y.append(risk_class)

    X = np.array(X)
    y = np.array(y)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = LogisticRegression(max_iter=1000, random_state=42, multi_class='multinomial')
    model.fit(X_scaled, y)

    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)

    return True


def assess_risk(findings, raw_results):
    """
    Full risk assessment pipeline.
    Returns: score (float), risk_level (str), severity_summary (dict), features (ndarray)
    """
    features = extract_features(findings, raw_results)
    score = compute_security_score(findings)
    risk_level = classify_risk(score, features)
    severity_summary = get_severity_summary(findings)

    return score, risk_level, severity_summary, features
