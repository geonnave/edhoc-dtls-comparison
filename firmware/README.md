Run with EDHOC:

```bash
make all flash term
```

Run with DTLS 1.3:

```bash
make all flash term SEC=dtls
```

When using more than one board:

```bash
DEBUG_ADAPTER_ID=000683380505 PORT=/dev/ttyACM3 make BOARD=nrf52840dk SEC=edhoc flash term
```

To flash for evaluation:

```bash
DEBUG_ADAPTER_ID=000683380505 PORT=/dev/ttyACM3 make BOARD=nrf52840dk SEC=edhoc MODE=eval TIMES=5 flash term
```
