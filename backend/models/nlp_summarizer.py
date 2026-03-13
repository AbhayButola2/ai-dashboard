from transformers import pipeline

class AlertSummarizer:
    def __init__(self):
        self._generator = None  # lazy load — only download on first call

    def _load(self):
        if self._generator is None:
            print("Loading NLP pipeline (first use)...")
            self._generator = pipeline("text2text-generation", model="google/flan-t5-small", device=-1)

    def summarize(self, record: dict) -> str:
        self._load()
        threat_type = record.get('threat_type', 'Unknown threat')
        source = record.get('source', 'Unknown source')
        tags = record.get('tags', '')
        severity = record.get('severity', 'Medium')
        prompt = f"Write a one-line urgent security alert about a {severity} severity {threat_type} from {source}. Tags: {tags}."
        try:
            result = self._generator(prompt, max_length=50, num_return_sequences=1)
            return result[0]['generated_text']
        except Exception:
            return f"{severity} Alert: {threat_type} detected from {source}."

# Singleton (lazy — model loads only on first summarize() call)
summarizer = AlertSummarizer()
