# dpa400dump
A wireshark extcap for the Unigraf DPA400 DisplayPort AUX channel monitor

## Preparations for Linux usage

The DPA400 USB interface is a FTDI 232R with custom VID/PID.
So make sure you have the ftdi_sio kernel module installed. Then add an udev rule that handles the custom IDs.

Add a file like 99-usbftdi.rules to /etc/udev/rules.d with the following content:
```
ACTION=="add", ATTRS{idVendor}=="16a6", ATTRS{idProduct}=="1000", RUN+="/sbin/modprobe ftdi_sio" RUN+="/bin/sh -c 'echo 16a6 1000 > /sys/bus/usb-serial/drivers/ftdi_sio/new_id'"
```
Maybe you have to force your system to update udev rules, but that is distro specific.

Then plugin your device. dmesg should show something like:
```
[28534.487368] usb 3-3.4: new full-speed USB device number 10 using xhci_hcd
[28534.586482] usb 3-3.4: New USB device found, idVendor=16a6, idProduct=1000
[28534.586490] usb 3-3.4: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[28534.586494] usb 3-3.4: Product: DPA-400 DisplayPort Analyzer
[28534.586498] usb 3-3.4: Manufacturer: Unigraf
[28534.586502] usb 3-3.4: SerialNumber: 1242C310
[28534.627165] usbcore: registered new interface driver ftdi_sio
[28534.627182] usbserial: USB Serial support registered for FTDI USB Serial Device
[28534.630424] ftdi_sio 3-3.4:1.0: FTDI USB Serial Device converter detected
[28534.630472] usb 3-3.4: Detected FT232RL
[28534.630822] usb 3-3.4: FTDI USB Serial Device converter now attached to ttyUSB1
```

## Preparations for Windows usage

Under windows you can simply use the driver that is coming with the device. You just have to find out, which serial port (COMx) is used.

## Installation

Simply copy dpa400dump.py to your wireshark extcap directory (Help > About Wireshark > Folders) and make 
sure it is executable.
After restarting wireshark you should see a DPA400 capture interface.
