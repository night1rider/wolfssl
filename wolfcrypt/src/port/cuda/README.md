You will need to have the CUDA libraries and toolchains installed to be able to use this. For the simplest
setup, I used the 'nvidia/cuda:12.3.2-devel-ubuntu22.04' container with the '--gpus=all' flag. Note that
Docker must be set up to allow passing through the CUDA instructions to the host. The container only needs
'automake' and 'libtool' installed: `apt update && apt install -y automake libtool`.

## Setting Up Docker with CUDA Support
Assuming the correct drivers are installed

### Pulling and Running the Container
1. Pull the NVIDIA CUDA container:
   ```bash
   docker pull nvidia/cuda:12.3.2-devel-ubuntu22.04
   ```

2. Run the container with the current directory mounted and GPU access:
   ```bash
   # Navigate to your wolfcrypt project directory
   cd /path/to/wolfcrypt
   
   # Start the container with the current directory mounted to /workspace
   docker run --gpus=all -it --rm \
     -v $(pwd):/workspace \
     -w /workspace \
     nvidia/cuda:12.3.2-devel-ubuntu22.04 bash
   ```

3. Inside the container, install required tools and build:
   ```bash
   apt update && apt install -y automake libtool
   
   # Now you can run your build commands
   ./configure --enable-all --disable-shared --disable-crl-monitor --enable-cuda CC=nvcc && make check
   ```

### Resolving NVIDIA Repository Key Warning

If you see a warning about the NVIDIA key being stored in a legacy trusted.gpg keyring, fix it with:

```bash
# Create the keyring directory if it doesn't exist
mkdir -p /etc/apt/keyrings

# Download the NVIDIA GPG key and add it to the new location
curl -fsSL https://developer.download.nvidia.com/compute/cuda/repos/debian12/x86_64/3bf863cc.pub | gpg --dearmor -o /etc/apt/keyrings/nvidia-cuda.gpg

# Update the repository configuration
sed -i 's|deb https://developer.download.nvidia.com|deb [signed-by=/etc/apt/keyrings/nvidia-cuda.gpg] https://developer.download.nvidia.com|' /etc/apt/sources.list.d/cuda*.list

# Update package lists
apt update
```

This code was tested with the following:
    ./configure --enable-all --disable-shared --disable-crl-monitor --enable-cuda CC=nvcc && make check

There are still things that can be done to optimize, but the basic functionality is there.


 ./configure --enable-all --disable-shared --disable-crl-monitor --enable-cuda --enable-intelasm=no --enable-kyber --enable-dilithium CC=nvcc && make check

With CPU (--enable-cuda --enable-intelasm=no):s
```
------------------------------------------------------------------------------
 wolfSSL version 5.7.6
------------------------------------------------------------------------------
ML-KEM 512    128  key gen     70900 ops took 1.001 sec, avg 0.014 ms, 70851.654 ops/sec
ML-KEM 512    128    encap     62700 ops took 1.001 sec, avg 0.016 ms, 62621.721 ops/sec
ML-KEM 512    128    decap     44100 ops took 1.001 sec, avg 0.023 ms, 44047.334 ops/sec
ML-KEM 768    192  key gen     43000 ops took 1.000 sec, avg 0.023 ms, 42980.714 ops/sec
ML-KEM 768    192    encap     38700 ops took 1.002 sec, avg 0.026 ms, 38616.843 ops/sec
ML-KEM 768    192    decap     28500 ops took 1.002 sec, avg 0.035 ms, 28448.790 ops/sec
ML-KEM 1024   256  key gen     27600 ops took 1.003 sec, avg 0.036 ms, 27523.950 ops/sec
ML-KEM 1024   256    encap     25400 ops took 1.001 sec, avg 0.039 ms, 25370.983 ops/sec
ML-KEM 1024   256    decap     19700 ops took 1.005 sec, avg 0.051 ms, 19603.909 ops/sec
ML-DSA    44  key gen     23300 ops took 1.002 sec, avg 0.043 ms, 23261.489 ops/sec
ML-DSA    44     sign      5600 ops took 1.017 sec, avg 0.182 ms, 5507.811 ops/sec
ML-DSA    44   verify     21000 ops took 1.002 sec, avg 0.048 ms, 20953.335 ops/sec
ML-DSA    65  key gen     12700 ops took 1.003 sec, avg 0.079 ms, 12664.178 ops/sec
ML-DSA    65     sign      3700 ops took 1.016 sec, avg 0.275 ms, 3642.474 ops/sec
ML-DSA    65   verify     13400 ops took 1.000 sec, avg 0.075 ms, 13395.599 ops/sec
ML-DSA    87  key gen      8700 ops took 1.008 sec, avg 0.116 ms, 8629.743 ops/sec
ML-DSA    87     sign      3000 ops took 1.026 sec, avg 0.342 ms, 2923.017 ops/sec
ML-DSA    87   verify      8300 ops took 1.009 sec, avg 0.122 ms, 8228.921 ops/sec
Benchmark complete
```


With CPU (no --enable-cuda --enable-intelasm=no)
```
------------------------------------------------------------------------------
 wolfSSL version 5.7.6
------------------------------------------------------------------------------
ML-KEM 512    128  key gen     74800 ops took 1.001 sec, avg 0.013 ms, 74700.745 ops/sec
ML-KEM 512    128    encap     62100 ops took 1.001 sec, avg 0.016 ms, 62028.112 ops/sec
ML-KEM 512    128    decap     43400 ops took 1.002 sec, avg 0.023 ms, 43320.677 ops/sec
ML-KEM 768    192  key gen     45000 ops took 1.001 sec, avg 0.022 ms, 44970.804 ops/sec
ML-KEM 768    192    encap     38200 ops took 1.002 sec, avg 0.026 ms, 38126.870 ops/sec
ML-KEM 768    192    decap     28100 ops took 1.002 sec, avg 0.036 ms, 28055.605 ops/sec
ML-KEM 1024   256  key gen     28400 ops took 1.002 sec, avg 0.035 ms, 28347.634 ops/sec
ML-KEM 1024   256    encap     25200 ops took 1.003 sec, avg 0.040 ms, 25118.900 ops/sec
ML-KEM 1024   256    decap     19400 ops took 1.005 sec, avg 0.052 ms, 19312.538 ops/sec
ML-DSA    44  key gen     23100 ops took 1.000 sec, avg 0.043 ms, 23098.062 ops/sec
ML-DSA    44     sign      5600 ops took 1.010 sec, avg 0.180 ms, 5545.298 ops/sec
ML-DSA    44   verify     20900 ops took 1.003 sec, avg 0.048 ms, 20828.481 ops/sec
ML-DSA    65  key gen     12600 ops took 1.003 sec, avg 0.080 ms, 12563.982 ops/sec
ML-DSA    65     sign      3600 ops took 1.022 sec, avg 0.284 ms, 3521.769 ops/sec
ML-DSA    65   verify     13400 ops took 1.007 sec, avg 0.075 ms, 13307.278 ops/sec
ML-DSA    87  key gen      8600 ops took 1.000 sec, avg 0.116 ms, 8597.344 ops/sec
ML-DSA    87     sign      3000 ops took 1.008 sec, avg 0.336 ms, 2977.640 ops/sec
ML-DSA    87   verify      8300 ops took 1.011 sec, avg 0.122 ms, 8207.457 ops/sec
Benchmark complete
```


With GPU (--enable-cuda --enable-intelasm=no CFLAG="WC_MLKEM_CUDA")
```
ML-KEM 512    128  key gen     71300 ops took 1.000 sec, avg 0.014 ms, 71283.073 ops/sec
ML-KEM 512    128    encap     62600 ops took 1.001 sec, avg 0.016 ms, 62539.165 ops/sec
ML-KEM 512    128    decap     44000 ops took 1.002 sec, avg 0.023 ms, 43914.230 ops/sec
ML-KEM 768    192  key gen     43100 ops took 1.001 sec, avg 0.023 ms, 43041.845 ops/sec
ML-KEM 768    192    encap     38700 ops took 1.001 sec, avg 0.026 ms, 38659.491 ops/sec
ML-KEM 768    192    decap     28400 ops took 1.000 sec, avg 0.035 ms, 28398.064 ops/sec
ML-KEM 1024   256  key gen     27600 ops took 1.002 sec, avg 0.036 ms, 27550.362 ops/sec
ML-KEM 1024   256    encap     25500 ops took 1.003 sec, avg 0.039 ms, 25419.674 ops/sec
ML-KEM 1024   256    decap     19700 ops took 1.005 sec, avg 0.051 ms, 19606.872 ops/sec
ML-DSA    44  key gen     23500 ops took 1.002 sec, avg 0.043 ms, 23452.511 ops/sec
ML-DSA    44     sign       400 ops took 1.099 sec, avg 2.747 ms, 364.044 ops/sec
ML-DSA    44   verify      1100 ops took 1.059 sec, avg 0.963 ms, 1038.853 ops/sec
ML-DSA    65  key gen     12700 ops took 1.002 sec, avg 0.079 ms, 12676.420 ops/sec
ML-DSA    65     sign       300 ops took 1.159 sec, avg 3.864 ms, 258.770 ops/sec
ML-DSA    65   verify       800 ops took 1.066 sec, avg 1.332 ms, 750.697 ops/sec
ML-DSA    87  key gen      8800 ops took 1.007 sec, avg 0.114 ms, 8737.538 ops/sec
ML-DSA    87     sign       300 ops took 1.305 sec, avg 4.349 ms, 229.957 ops/sec
ML-DSA    87   verify       600 ops took 1.040 sec, avg 1.734 ms, 576.842 ops/sec
```