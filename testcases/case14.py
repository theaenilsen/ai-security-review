import yaml


def load_config(uploaded_text):
    config = yaml.safe_load(uploaded_text)
    return config.get("settings", {})
