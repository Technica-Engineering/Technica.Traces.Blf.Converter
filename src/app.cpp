/*
  Copyright (c) 2020 Technica Engineering GmbH
  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/

#include <array>
#include <codecvt>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <map>

#include <Vector/BLF.h>
#include <light_pcapng_ext.h>
#include "endianness.h"
#include "pcapng_exporter/lin.h"
#include "pcapng_exporter/linktype.h"
#include "pcapng_exporter/pcapng_exporter.hpp"

using namespace Vector::BLF;

#define HAS_FLAG(var,pos) ((var) & (1<<(pos)))

#define NANOS_PER_SEC 1000000000
#define LINKTYPE_ETHERNET 1 
#define LINKTYPE_CAN_SOCKETCAN 227 

#define DIR_IN    1
#define DIR_OUT   2

class CanFrame {
private:
	uint8_t raw[72] = { 0 };
public:

	uint32_t id() {
		return ntoh32(*(uint32_t*)raw) & 0x1fffffff;
	}

	void id(uint32_t value) {
		uint8_t id_flags = *raw & 0xE0;
		*(uint32_t*)raw = hton32(value);
		*raw |= id_flags;
	}

	bool ext() {
		return (*raw & 0x80) != 0;
	}
	void ext(bool value) {
		uint8_t masked = *raw & 0x7F;
		*raw = masked | value << 7;
	}

	bool rtr() {
		return (*raw & 0x40) != 0;
	}
	void rtr(bool value) {
		uint8_t masked = *raw & 0xBF;
		*raw = masked | value << 6;
	}

	bool err() {
		return (*raw & 0x20) != 0;
	}
	void err(bool value) {
		uint8_t masked = *raw & 0xDF;
		*raw = masked | value << 5;
	}

	bool brs() {
		return (*(raw + 5) & 0x01) != 0;
	}
	void brs(bool value) {
		uint8_t masked = *(raw + 5) & 0xFE;
		*(raw + 5) = masked | value << 0;
	}

	bool esi() {
		return (*(raw + 5) & 0x02) != 0;
	}
	void esi(bool value) {
		uint8_t masked = *(raw + 5) & 0xFD;
		*(raw + 5) = masked | value << 1;
	}

	uint8_t len() {
		return *(raw + 4);
	}
	void len(uint8_t value) {
		*(raw + 4) = value;
	}

	const uint8_t* data() {
		return raw + 8;
	}
	void data(const uint8_t* value, size_t size) {
		memcpy(raw + 8, value, size);
	}

	const uint8_t* bytes() {
		return raw;
	}

	const uint8_t size() {
		return len() + 8;
	}

};

template <class ObjHeader>
int write_packet(
	pcapng_exporter::PcapngExporter exporter,
	uint16_t link_type,
	ObjHeader* oh,
	uint32_t length,
	const uint8_t* data,
	uint64_t date_offset_ns,
	uint32_t flags = 0
) {

	light_packet_interface interface = { 0 };
	interface.link_type = link_type;
	std::string name = std::to_string(oh->channel);
	char name_str[256] = { 0 };
	memcpy(name_str, name.c_str(), sizeof(char) * std::min((size_t)255, name.length()));
	interface.name = name_str;
	
	uint64_t ts_resol = 0;
	switch (oh->objectFlags) {
	case ObjectHeader::ObjectFlags::TimeTenMics:
		ts_resol = 100000;
	case ObjectHeader::ObjectFlags::TimeOneNans:
		ts_resol = NANOS_PER_SEC;
		break;
	default:
		fprintf(stderr, "ERROR: The timestamp format is unknown (not 10us nor ns)!\n");
		return -3;
	}
	interface.timestamp_resolution = ts_resol;

	light_packet_header header = { 0 };

	uint64_t ts = (NANOS_PER_SEC / ts_resol) * oh->objectTimeStamp + date_offset_ns;

	header.timestamp.tv_sec = ts / NANOS_PER_SEC;
	header.timestamp.tv_nsec = ts % NANOS_PER_SEC;

	header.captured_length = length;
	header.original_length = length;

	exporter.write_packet(oh->channel ,interface, header, data);
	return 0;
}

// CAN_MESSAGE = 1
void write(pcapng_exporter::PcapngExporter exporter, CanMessage* obj, uint64_t date_offset_ns) {
	CanFrame can;

	can.id(obj->id);
	can.rtr(HAS_FLAG(obj->flags, 7));
	can.len(obj->dlc);
	can.data(obj->data.data(), obj->data.size());

	uint32_t flags = HAS_FLAG(obj->flags, 0) ? DIR_OUT : DIR_IN;
	write_packet(exporter, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), date_offset_ns, flags);
}

// CAN_MESSAGE2
void write(pcapng_exporter::PcapngExporter exporter, CanMessage2* obj, uint64_t date_offset_ns) {
	CanFrame can;

	can.id(obj->id);
	can.rtr(HAS_FLAG(obj->flags, 7));
	can.len(obj->dlc);
	can.data(obj->data.data(), obj->data.size());

	uint32_t flags = HAS_FLAG(obj->flags, 0) ? DIR_OUT : DIR_IN;
	
	write_packet(exporter, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), date_offset_ns, flags);
}

template <class CanError>
void write_can_error(pcapng_exporter::PcapngExporter exporter, CanError* obj, uint64_t date_offset_ns) {

	CanFrame can;
	can.err(true);
	can.len(8);
	write_packet(exporter, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), date_offset_ns);
}

// CAN_ERROR = 2
void write(pcapng_exporter::PcapngExporter exporter, CanErrorFrame* obj, uint64_t date_offset_ns) {

	write_can_error(exporter, obj, date_offset_ns);
}

// CAN_ERROR_EXT = 73
void write(pcapng_exporter::PcapngExporter exporter, CanErrorFrameExt* obj, uint64_t date_offset_ns) {

	write_can_error(exporter, obj, date_offset_ns);
}

// CAN_FD_MESSAGE = 100
void write(pcapng_exporter::PcapngExporter exporter, CanFdMessage* obj, uint64_t date_offset_ns) {

	CanFrame can;

	can.id(obj->id);

	can.rtr(HAS_FLAG(obj->flags, 7));

	can.esi(HAS_FLAG(obj->canFdFlags, 2));
	can.brs(HAS_FLAG(obj->canFdFlags, 1));

	can.len(obj->validDataBytes);
	can.data(obj->data.data(), obj->data.size());

	uint32_t flags = HAS_FLAG(obj->flags, 0) ? DIR_OUT : DIR_IN;

	write_packet(exporter, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), date_offset_ns, flags);
}

// CAN_FD_MESSAGE_64 = 101
void write(pcapng_exporter::PcapngExporter exporter, CanFdMessage64* obj, uint64_t date_offset_ns) {

	CanFrame can;

	can.id(obj->id);

	can.rtr(HAS_FLAG(obj->flags, 4));

	can.esi(HAS_FLAG(obj->flags, 14));
	can.brs(HAS_FLAG(obj->flags, 13));

	can.len(obj->validDataBytes);
	can.data(obj->data.data(), obj->data.size());

	// TODO obj->crc

	uint32_t flags = HAS_FLAG(obj->flags, 6) || HAS_FLAG(obj->flags, 7) ? DIR_OUT : DIR_IN;

	write_packet(exporter, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), date_offset_ns);
}

// CAN_FD_ERROR_64 = 104
void write(pcapng_exporter::PcapngExporter exporter, CanFdErrorFrame64* obj, uint64_t date_offset_ns) {

	write_can_error(exporter, obj, date_offset_ns);
}

// ETHERNET_FRAME = 71
void write(pcapng_exporter::PcapngExporter exporter, EthernetFrame* obj, uint64_t date_offset_ns) {

	uint32_t flags = 0;
	switch (obj->dir)
	{
	case 0:
		flags = DIR_IN;
		break;
	case 1:
		flags = DIR_OUT;
		break;
	}

	std::vector<uint8_t> eth;
	// Pre allocate to remove need of reallocation
	eth.reserve(14 + 4 + obj->payLoad.size());

	eth.insert(eth.end(), obj->destinationAddress.begin(), obj->destinationAddress.end());
	eth.insert(eth.end(), obj->sourceAddress.begin(), obj->sourceAddress.end());

	if (obj->tpid) {
		std::array<uint8_t, 4> vlan = {
			(uint8_t)(obj->tpid >> 8),
			(uint8_t)obj->tpid,
			(uint8_t)(obj->tci >> 8),
			(uint8_t)obj->tci
		};
		eth.insert(eth.end(), vlan.begin(), vlan.end());
	}

	eth.push_back((uint8_t)(obj->type >> 8));
	eth.push_back((uint8_t)obj->type);

	eth.insert(eth.end(), obj->payLoad.begin(), obj->payLoad.end());

	write_packet(exporter, LINKTYPE_ETHERNET, obj, eth.size(), eth.data(), date_offset_ns, flags);
}

template <class TEthernetFrame>
void write_ethernet_frame(pcapng_exporter::PcapngExporter exporter, TEthernetFrame* obj, uint64_t date_offset_ns) {
	std::vector<uint8_t> eth(obj->frameData);

	if (HAS_FLAG(obj->flags, 3)) {
		uint8_t* crcPtr = (uint8_t*)&obj->frameChecksum;
		std::vector<uint8_t> crc(crcPtr, crcPtr + 4);
		eth.insert(eth.end(), crc.begin(), crc.end());
	}

	uint32_t flags = 0;
	switch (obj->dir)
	{
	case 0:
		flags = DIR_IN;
		break;
	case 1:
		flags = DIR_OUT;
		break;
	}

	write_packet(exporter, LINKTYPE_ETHERNET, obj, (uint32_t)eth.size(), eth.data(), date_offset_ns, flags);

}

// ETHERNET_FRAME_EX = 120
void write(pcapng_exporter::PcapngExporter exporter, EthernetFrameEx* obj, uint64_t date_offset_ns) {

	write_ethernet_frame(exporter, obj, date_offset_ns);
}

// ETHERNET_FRAME_FORWARDED = 121
void write(pcapng_exporter::PcapngExporter exporter, EthernetFrameForwarded* obj, uint64_t date_offset_ns) {

	write_ethernet_frame(exporter, obj, date_offset_ns);
}

uint64_t calculate_startdate(Vector::BLF::File* infile) {
	Vector::BLF::SYSTEMTIME startTime;
	startTime = infile->fileStatistics.measurementStartTime;

	struct tm tms = { 0 };
	tms.tm_year = startTime.year - 1900;
	tms.tm_mon = startTime.month - 1;
	tms.tm_mday = startTime.day;
	tms.tm_hour = startTime.hour;
	tms.tm_min = startTime.minute;
	tms.tm_sec = startTime.second;

	time_t ret = mktime(&tms);

	ret *= 1000;
	ret += startTime.milliseconds;
	ret *= 1000 * 1000;

	return ret;
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		fprintf(stderr, "Usage %s [infile] [outfile] [mappingfile]\n", argv[0]);
		return 1;
	}

	Vector::BLF::File infile;
	infile.open(argv[1]);
	if (!infile.is_open()) {
		fprintf(stderr, "Unable to open: %s\n", argv[1]);
		return 1;
	}
	light_pcapng outfile = light_pcapng_open(argv[2], "wb");
	pcapng_exporter::PcapngExporter exporter = pcapng_exporter::PcapngExporter(argv[2], argv[3]);

	uint64_t startDate_ns = calculate_startdate(&infile);

	while (infile.good()) {
		ObjectHeaderBase* ohb = nullptr;

		/* read and capture exceptions, e.g. unfinished files */
		try {
			ohb = infile.read();
		}
		catch (std::runtime_error& e) {
			std::cout << "Exception: " << e.what() << std::endl;
		}
		if (ohb == nullptr) {
			break;
		}
		/* Object */
		switch (ohb->objectType) {

		case ObjectType::CAN_MESSAGE:
			write(exporter, reinterpret_cast<CanMessage*>(ohb), startDate_ns);
			break;

		case ObjectType::CAN_ERROR:
			write(exporter, reinterpret_cast<CanErrorFrame*>(ohb), startDate_ns);
			break;

		case ObjectType::CAN_FD_MESSAGE:
			write(exporter, reinterpret_cast<CanFdMessage*>(ohb), startDate_ns);
			break;

		case ObjectType::CAN_FD_MESSAGE_64:
			write(exporter, reinterpret_cast<CanFdMessage64*>(ohb), startDate_ns);
			break;

		case ObjectType::CAN_FD_ERROR_64:
			write(exporter, reinterpret_cast<CanFdErrorFrame64*>(ohb), startDate_ns);
			break;

		case ObjectType::ETHERNET_FRAME:
			write(exporter, reinterpret_cast<EthernetFrame*>(ohb), startDate_ns);
			break;

		case ObjectType::CAN_ERROR_EXT:
			write(exporter, reinterpret_cast<CanErrorFrameExt*>(ohb), startDate_ns);
			break;

		case ObjectType::CAN_MESSAGE2:
			write(exporter, reinterpret_cast<CanMessage2*>(ohb), startDate_ns);
			break;

		case ObjectType::ETHERNET_FRAME_EX:
			write(exporter, reinterpret_cast<EthernetFrameEx*>(ohb), startDate_ns);
			break;

		case ObjectType::ETHERNET_FRAME_FORWARDED:
			write(exporter, reinterpret_cast<EthernetFrameForwarded*>(ohb), startDate_ns);
			break;
		}

		/* delete object */
		delete ohb;
	}

	infile.close();
	light_pcapng_close(outfile);

	return 0;
}
