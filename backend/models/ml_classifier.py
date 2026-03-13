import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import numpy as np

class ThreatClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        self.encoder = LabelEncoder()
        self._train_mock_data()

    def _train_mock_data(self):
        data = {
            'threat_type': ['botnet', 'malware', 'phishing', 'ransomware', 'unknown', 'c2'],
            'tags_count': [3, 1, 0, 5, 0, 4],
            'source': ['URLhaus', 'URLhaus', 'ThreatFox', 'ThreatFox', 'ThreatFox', 'URLhaus'],
            'severity': ['High', 'Medium', 'Low', 'Critical', 'Low', 'Critical']
        }
        df = pd.DataFrame(data)
        df['threat_type_enc'] = self.encoder.fit_transform(df['threat_type'])
        df['source_enc'] = df['source'].apply(lambda x: 1 if x == 'URLhaus' else 0)
        X = df[['threat_type_enc', 'tags_count', 'source_enc']]
        y = df['severity']
        self.model.fit(X, y)

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        features = pd.DataFrame()
        # Ensure 'unknown' is in the encoder classes
        if 'unknown' not in self.encoder.classes_:
            self.encoder.classes_ = np.append(self.encoder.classes_, 'unknown')

        def safe_encode(val):
            v = str(val).lower()
            if v in self.encoder.classes_:
                return int(self.encoder.transform([v])[0])
            return int(self.encoder.transform(['unknown'])[0])

        normalized = df.get('threat_type', pd.Series(['unknown'] * len(df))).astype(str).str.lower()
        features['threat_type_enc'] = normalized.apply(safe_encode)
        features['tags_count'] = df.get('tags', pd.Series([''] * len(df))).apply(
            lambda x: len(str(x).split(',')) if x else 0)
        features['source_enc'] = df.get('source', pd.Series([''] * len(df))).apply(
            lambda x: 1 if x == 'URLhaus' else 0)
        return features

    def predict(self, df: pd.DataFrame) -> list:
        if df.empty:
            return []
        return list(self.model.predict(self.extract_features(df)))

# Singleton
classifier = ThreatClassifier()
