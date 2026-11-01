import yaml


def load_config(uploaded_text):
    config = yaml.load(uploaded_text, Loader=yaml.Loader)
    return config.get("settings", {})
