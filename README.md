The error you're seeing:

fatal error: pcap.h: No such file or directory


means that the Go package you're trying to use (gopacket/pcap) depends on libpcap, which is a C library for packet capture. The Go wrapper is trying to include pcap.h, but it can't find it because the development headers for libpcap aren't installed on your system.

✅ Solution: Install the libpcap development package

Since you're using a Linux system (likely Ubuntu or Debian-based, judging from the shell prompt), you need to install libpcap-dev.

Run this command:
sudo apt update
sudo apt install libpcap-dev

This installs both the library and the necessary pcap.h header file.