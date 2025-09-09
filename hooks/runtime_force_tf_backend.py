import os
os.environ.setdefault("KERAS_BACKEND", "tensorflow")
os.environ.setdefault("KERAS_BACKEND_AUTO", "0")
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
