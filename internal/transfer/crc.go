// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package transfer

import "hash/crc32"

// crc16 is CRC-16/XMODEM: polynomial 0x1021, no reflection, no final XOR. ZMODEM's
// 16-bit header and subpacket checksum is this algorithm, computed over the header's
// type and data bytes, or a subpacket's payload and terminator byte.
func crc16(data []byte) uint16 {
	var crc uint16
	for _, value := range data {
		crc ^= uint16(value) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// crc32sum is ZMODEM's 32-bit checksum: the same CRC-32 as PKZip and gzip, which
// hash/crc32's IEEE table already computes with the init and final complement built in.
func crc32sum(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}
