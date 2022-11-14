#!/usr/bin/env python3

import argparse
import re
import socket
import time
from enum import IntEnum
from struct import pack, unpack


class ErrorCodeType(IntEnum):
    ERROR_CODE_OK = 0x00
    ERROR_CODE_STA_NOT_FOUND = 0x01
    ERROR_CODE_BAD_MSG = 0x02

class MessageType(IntEnum):
    MSG_REGISTER_STA = 0x01
    MSG_UNREGISTER_STA = 0x02
    MSG_GET_STA_STATS = 0x04
    MSG_GET_STA_WMI_STATS = 0x08
    MSG_CHANGE_KEEPALIVE_TIMEOUT_MS = 0x10
    MSG_CHANGE_PACKET_PERIODICITY_MS = 0x20
    
def connect_and_poll_rssi(socket_path: str, mac: str) -> None:
    trimmed_mac = mac.replace(':', '')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        print(f"Connecting to {socket_path}...")
        client.connect(socket_path)
        sta_mac = bytearray.fromhex(trimmed_mac)
        packed = pack('i6B', MessageType.MSG_REGISTER_STA, sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5])
        client.send(packed)
        rxd = client.recv(256)
        error_code, response_station_mac = unpack('i6s', rxd)
        print(f"Request to register station '{mac}' error code: {error_code} response STA MAC {response_station_mac}")
        while True:
            # occasionally ask for link metrics stats
            packed = pack('i6B', MessageType.MSG_GET_STA_STATS, sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5])
            client.send(packed)
            rx = client.recv(256)
            print(f"rx is {rx}")
            err, resp_sta_mac, rssi, channel_num, timestamp = unpack('<i6sbhQ', rx)
            print(f'STA {resp_sta_mac} err {err} channel number {channel_num}, rssi {rssi}, timestamp {timestamp}')
            time.sleep(1)

def validate_mac(mac: str) -> bool:
    return re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--socket_path', help='Absolute path to the Unix server socket to connect to.', required=True)
    parser.add_argument('--sta_mac', help='The MAC address of the station to request link metrics for.', required=True)
    args = parser.parse_args()
    if not validate_mac(args.sta_mac):
        print(f"STA MAC {args.sta_mac} seems malformed. Try again. Format expected: aa:bb:cc:dd:ee:ff")
        exit(1)
    connect_and_poll_rssi(args.socket_path, args.sta_mac)

if __name__ == '__main__':
    main()
