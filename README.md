# Inverter Security Scanner Project

## Introduction

This project is trying to ``scan'' radio signals emitted from power inverters to determine of any unauthorized signals (i.e. not from standard fucntions like firmware updates) are emitted. To do so, we will assume othw following input:

### Input

We are given raw input data from a directional antenna directed at the inverter. We should construct the software in such a way that extending one function would enable it to run on both a laptop and a smaller computer like a Raspberry Pi Zero.

## Assumed Knowns

For us to accurately flag insecure inverters, we need to assume the following are known to us:

- We have an idea of tha frequency range (or a specific frequency) that authorized signals come from, ANY other frequency ranges within a certain decibel level of our main frequency should be flagged.
    - We should take our RF data either through a test stream or a SDR, using rtl_power to parse the data and detect unauthorized frequencies.
- We know the IP addresses of authorized signals, ANY other IP address is considered unauthorized. These IP address permissions should change depending on the request type.
- We know the type of data given by our firmware update, ANY other data should be flagged.
- Generally, packet matching is more complicated, but include some simple pattern-matching logic (though regex preferrably) in the event we can use this to distinguish authorization.

[^note] We also need a way to connect with the inverter's HTTPS endpoint to spoof the signals. We have the inverter in our possesion, and thus we should be able to recover our HTTPS signal.

## Rough Sketch of Computer Logic

We'll divide our program into two threads. Our first thread scans the raw RF data to detect different critical frequencies, and if an unauthorized signal goes out, flag it. This thread should run if we feed test data into our device, or we introduce an SDR device that starts sniffing the frequencies. Otherwise, the thread should sleep.

Our second thread will find and scan incoming and outgoing HTTPS requests. If any part of these requests don't match our authorized signals in a similar manner to the rules above, flag it. In scanning the HTTPS requests, we should also send metrics to our central we server using the following [open-source library](https://github.com/szlaskidaniel/solar-inverter-modbus-registers)

When we flag an inverter, we should notify a central web server, which takes the inverter ID, which it then will use to notify the end user. Assumes this server endpoint exists, and make a placeholder name for it, outling the format the HTTPS request takes.

## BOM

[Raspberry Pi](https://www.microcenter.com/product/704295/raspberry-pi-5-1gb)
[RTL-SDR](https://www.microcenter.com/product/711017/rtl2832u-r828d-tcxo-bios-t-hf-software-defined-radio-with-dipole-antenna-kit)
SD card
