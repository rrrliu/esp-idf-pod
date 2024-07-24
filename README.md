# Get Started Examples

Simple code to get started with ESP32 and ESP-IDF.

See the [README.md](../README.md) file in the upper level [examples](../) directory for more information about examples.

# Instructions to run blink

Based on the instructions from the [Seeed Xiao docs](https://wiki.seeedstudio.com/xiao_idf).

Plug in your ESP32-S3 and run this command to get the port.
```
ls /dev/cu.*
```

To build and setup, run these following commands:
```
cd blink/
idf.py set-target esp32s3
idf.py menuconfig
# Set LED type to GPIO and GPIO number to 21
idf.py build
idf.py -p PORT flash # use the /dev/cu... PORT from above
```
