from sklearn.ensemble import IsolationForest
import numpy as np

# Dummy data simulation
X_train = np.random.rand(100, 4)  # Simulated feature vectors
model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
model.fit(X_train)

def extract_features(packet):
    # Extract dummy features (you can make these more realistic)
    ip_len = len(packet) if packet else 0
    has_payload = int(packet.haslayer(Raw))
    protocol = packet[IP].proto if IP in packet else 0
    return np.array([ip_len, has_payload, protocol, int(TCP in packet)]).reshape(1, -1)

def is_anomalous(packet):
    try:
        features = extract_features(packet)
        prediction = model.predict(features)
        return prediction[0] == -1
    except Exception as e:
        print(f"[ML ERROR] {e}")
        return False
