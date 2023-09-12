# Collecting data:
- To capture `*.pcap` files, use RIOT's `example/sniffer` code. See its README for more info.
It works out of the box with the nRF52840.
- To generate `*_pcap.csv` files, run `python3 packet_loader.py`.
For this to work, the acual corresponding `*.pcap` files must be available.
This step is only needed because `pyshark` [still cannot be run within a jupyter notebook](https://github.com/KimiNewt/pyshark/pull/291).
- To collect memory information, run `python3 measure_memory.py <destination folder>` (in the `firmware` folder).
This will (1) compile the binary, measure it with `size` and (2) flash it and, via serial, measure RAM with RIOT's `ps`.

# Analysing it:

1. Make sure you have all files needed in the cells that instantiate `Experiment` and call `simulate_time_on_air`.
2. Run all cells in the `comparison.ipynb` notebook.

This will generate several tables (dataframes) and plots.

# Dependencies
Install python's deps with `pip install -r requirements.txt`.

For sniffer and for running the firmware, [RIOT](https://github.com/RIOT-OS/RIOT) is also needed.

The firmware also depends on a statically-compiled version of `edhoc_rs` with CC310 crypto backend.
