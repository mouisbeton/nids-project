# Use Debian slim as a lighter glibc-compatible base
FROM debian:12-slim

# Avoid tzdata interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install BCC tools, kernel headers, and Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    bpfcc-tools \
    python3-bpfcc \
    linux-headers-generic \
    python3 \
    python3-pip \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt /app/

# Install the Python dependencies (PyTorch, scikit-learn, etc.)
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Now copy the rest of the application files
COPY integrated_nids.py /app/
COPY ae_ids_model.pth /app/
COPY scaler.pkl /app/
COPY decision_tree.pkl /app/

# Ensure the BPF BCC python libraries are in the path
ENV PYTHONPATH="/usr/lib/python3/dist-packages"

# The default command runs the NIDS script. You overide the interface argument in docker run
ENTRYPOINT ["python3", "integrated_nids.py"]
CMD ["wlo1"]
