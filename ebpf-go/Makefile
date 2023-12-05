.PHONY: all gen install pull
all:
	GOOS=android GOARCH=arm64 go build -trimpath .

gen:
	go generate

install:
	adb  push ebpftest /data/local/tmp
	adb  shell chmod +x /data/local/tmp/ebpftest

pull:
	adb pull /data/local/tmp/2.pcap .