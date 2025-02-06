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

#include <Vector/BLF.h>
#include <light_pcapng_ext.h>
#include "endianness.h"
#include <pcapng_exporter/lin.h>
#include <pcapng_exporter/linktype.h>
#include <pcapng_exporter/pcapng_exporter.hpp>
#include <args.hxx>

#include "channels.hpp"

using namespace Vector::BLF;

#define HAS_FLAG(var,pos) ((var) & (1<<(pos)))

#define NANOS_PER_SEC 1000000000
#define TIMESTAMP_MASK 0x7fffffffffffffff

#define DIR_IN    1
#define DIR_OUT   2

// Enumerations
enum class FlexRayPacketType
{
	FlexRayFrame = 1,    // FlexRay Frame
	FlexRaySymbol = 2     // FlexRay Symbol
};

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

template<class ObjectHeaderGeneric>
std::uint64_t calculate_ts_res(ObjectHeaderGeneric* oh)
{
	uint64_t ts_resol = 0;
	switch (oh->objectFlags) {
	case ObjectHeader::ObjectFlags::TimeTenMics:
		ts_resol = 100000;
		break;
	case ObjectHeader::ObjectFlags::TimeOneNans:
		ts_resol = NANOS_PER_SEC;
		break;
	default:
		fprintf(stderr, "ERROR: The timestamp format is unknown (not 10us nor ns)!\n");
		break;
	}
	return ts_resol;
}

template<class ObjectHeaderGeneric>
pcapng_exporter::frame_header generate_header(
	ObjectHeaderGeneric* oh,
	std::uint64_t date_offset_ns)
{
	pcapng_exporter::frame_header header = pcapng_exporter::frame_header();
	header.channel_id = oh->channel;
	header.timestamp_resolution = calculate_ts_res(oh);
	uint64_t relative_timestamp = (NANOS_PER_SEC / header.timestamp_resolution) * oh->objectTimeStamp;
	uint64_t ts = (relative_timestamp & TIMESTAMP_MASK) + (date_offset_ns & TIMESTAMP_MASK);
	header.timestamp.tv_sec = ts / NANOS_PER_SEC;
	header.timestamp.tv_nsec = ts % NANOS_PER_SEC;
	return header;
}

template <class ObjHeader>
int write_packet(
	pcapng_exporter::PcapngExporter exporter,
	uint16_t link_type,
	ObjHeader* oh,
	uint32_t length,
	const uint8_t* data,
	uint64_t date_offset_ns,
	uint32_t flags = 0,
	uint32_t hw_channel = 0
) {
	light_packet_interface interface = { 0 };
	interface.link_type = link_type;
	auto channel_id = 100000 * hw_channel + oh->channel;
	std::string name = std::to_string(channel_id);
	char name_str[256] = { 0 };
	memcpy(name_str, name.c_str(), sizeof(char) * std::min((size_t)255, name.length()));
	interface.name = name_str;

	uint64_t ts_resol = calculate_ts_res(oh);
	if (ts_resol == 0) return -3;

	/* since we convert to NS, we need to always set the output to NS */
	interface.timestamp_resolution = NANOS_PER_SEC;

	light_packet_header header = { 0 };
	uint64_t relative_timestamp = (NANOS_PER_SEC / ts_resol) * oh->objectTimeStamp;
	uint64_t ts = (relative_timestamp & TIMESTAMP_MASK) + (date_offset_ns & TIMESTAMP_MASK);
	header.timestamp.tv_sec = ts / NANOS_PER_SEC;
	header.timestamp.tv_nsec = ts % NANOS_PER_SEC;
	header.captured_length = length;
	header.original_length = length;
	header.flags = flags;

	exporter.write_packet(channel_id, interface, header, data);

	std::cout << "********************* \n interface.timestamp_resolution : \n";
	std::cout << interface.timestamp_resolution;
	std::cout << "\n ts_resol : \n";
	std::cout << ts_resol;
	std::cout << "\n relative_timestamp : \n";
	std::cout << relative_timestamp;
	std::cout << "\n relative_timestamp after mask : \n";
	std::cout << (relative_timestamp & TIMESTAMP_MASK);
	std::cout << "\n date_offset_ns : \n";
	std::cout << date_offset_ns;
	std::cout << "\n date_offset_ns after mask : \n";
	std::cout << (date_offset_ns & TIMESTAMP_MASK);
	std::cout << "\n header.timestamp.tv_sec : \n";
	std::cout << header.timestamp.tv_sec;
	std::cout << "\n header.timestamp.tv_nsec : \n";
	std::cout << header.timestamp.tv_nsec;
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
	write_packet(exporter, LINKTYPE_CAN, obj, can.size(), can.bytes(), date_offset_ns, flags);
}

// CAN_MESSAGE2
void write(pcapng_exporter::PcapngExporter exporter, CanMessage2* obj, uint64_t date_offset_ns) {
	CanFrame can;

	can.id(obj->id);
	can.rtr(HAS_FLAG(obj->flags, 7));
	can.len(obj->dlc);
	can.data(obj->data.data(), obj->data.size());

	uint32_t flags = HAS_FLAG(obj->flags, 0) ? DIR_OUT : DIR_IN;

	write_packet(exporter, LINKTYPE_CAN, obj, can.size(), can.bytes(), date_offset_ns, flags);
}

template <class CanError>
void write_can_error(pcapng_exporter::PcapngExporter exporter, CanError* obj, uint64_t date_offset_ns) {

	CanFrame can;
	can.err(true);
	can.len(8);
	write_packet(exporter, LINKTYPE_CAN, obj, can.size(), can.bytes(), date_offset_ns);
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

	write_packet(exporter, LINKTYPE_CAN, obj, can.size(), can.bytes(), date_offset_ns, flags);
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

	write_packet(exporter, LINKTYPE_CAN, obj, can.size(), can.bytes(), date_offset_ns);
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

	write_packet(exporter, LINKTYPE_ETHERNET, obj, (uint32_t)eth.size(), eth.data(), date_offset_ns, flags, obj->hardwareChannel);
}

// ETHERNET_FRAME_EX = 120
void write(pcapng_exporter::PcapngExporter exporter, EthernetFrameEx* obj, uint64_t date_offset_ns) {

	write_ethernet_frame(exporter, obj, date_offset_ns);
}

// ETHERNET_FRAME_FORWARDED = 121
void write(pcapng_exporter::PcapngExporter exporter, EthernetFrameForwarded* obj, uint64_t date_offset_ns) {

	write_ethernet_frame(exporter, obj, date_offset_ns);
}

void set_measurment_header(uint8_t& measurementHeader, FlexRayPacketType packetType, uint16_t channelMask = 0)
{
	/// Measurement Header (1 byte)
	// TI[0..6]: Type Index
	// 0x01: FlexRay Frame
	// 0x02: FlexRay Symbol
	switch (packetType)
	{
	case FlexRayPacketType::FlexRayFrame:
		measurementHeader = 0x01;
		break;
	case FlexRayPacketType::FlexRaySymbol:
		measurementHeader = 0x02;
		break;
	}
	// CH: Channel, indicates the Channel
	// 1	: Channel A
	// 2/3	: Channel B
	switch (channelMask)
	{
	case 1: /* Channel A */
		break;
	case 2: /* Channel B */
	case 3: /* Channel B */
		measurementHeader |= 0x80;
		break;
	}
}

void set_header_crc(uint16_t channelMask, uint16_t headerCrc1, uint16_t headerCrc2, uint16_t& headerCrc)
{
	// CH: Channel, indicates the Channel
	// 1	: Channel A
	// 2/3	: Channel B
	switch (channelMask)
	{
	case 1: /* Channel A */
		headerCrc = headerCrc1;
		break;
	case 2: /* Channel B */
	case 3: /* Channel B */
		headerCrc = headerCrc2;
		break;
	}
}

void set_header_flags(uint16_t frameState, uint8_t& headerFlags)
{
	if (HAS_FLAG(frameState, 0))
	{
		headerFlags |= 0x08; // Payload preample indicator bit set to 1
	}
	if (HAS_FLAG(frameState, 1))
	{
		headerFlags |= 0x02; // Sync. frame indicator bit set to 1
	}
	if (HAS_FLAG(frameState, 2))
	{
		headerFlags |= 0x10; // Reserved bit set to 1
	}
	if (!HAS_FLAG(frameState, 3))
	{
		headerFlags |= 0x04; // Null frame indicator bit set to 1
	}
	if (HAS_FLAG(frameState, 4))
	{
		headerFlags |= 0x01; // Startup frame indicator bit set to 1
	}
}

void set_header_flags_rcv_msg(uint32_t frameFlags, uint8_t& headerFlags)
{
	if (!HAS_FLAG(frameFlags, 0))
	{
		headerFlags |= 0x04; // Null frame indicator bit set to 1
	}
	if (HAS_FLAG(frameFlags, 2))
	{
		headerFlags |= 0x02; // Sync. frame indicator bit set to 1
	}
	if (HAS_FLAG(frameFlags, 3))
	{
		headerFlags |= 0x01; // Startup frame indicator bit set to 1
	}
	if (HAS_FLAG(frameFlags, 4))
	{
		headerFlags |= 0x08; // Payload preample indicator bit set to 1
	}
	if (HAS_FLAG(frameFlags, 5))
	{
		headerFlags |= 0x10; // Reserved bit set to 1
	}
}

void set_header(uint64_t& header, uint8_t headerFlags, uint64_t payloadLength, uint8_t cycleCount = 0, uint16_t frameId = 0, uint16_t headerCrc = 0)
{
	header = (static_cast<uint64_t>(headerFlags) << 35) | (static_cast<uint64_t>(payloadLength & 0x7F) << 17);
	if (cycleCount != 0)
	{
		header |= static_cast<uint64_t>(cycleCount & 0x3F);
	}
	if (frameId != 0)
	{
		header |= (static_cast<uint64_t>(frameId & 0x07FF) << 24);
	}
	if (headerCrc != 0)
	{
		header |= (static_cast<uint64_t>(headerCrc & 0x07FF) << 6);
	}

	// Convert from Host Byte Order to Network Byte Order (network order is big endian)
	header = hton64(header);
}

// FLEXRAY_DATA = 29
void write(pcapng_exporter::PcapngExporter exporter, FlexRayData* obj, uint64_t date_offset_ns) {

	uint64_t header = 0;
	uint8_t headerFlags = 0;
	std::array<uint8_t, 261> flexrayData;

	memset(&flexrayData, 0, sizeof(flexrayData));

	/// Measurement Header (1 byte)
	set_measurment_header(flexrayData[0], FlexRayPacketType::FlexRayFrame);

	/// Error Flags Information (1 byte) -> set to 0

	/// FlexRay Frame Header (5 bytes)
	//  - Header flags
	headerFlags |= 0x04; // Null Frame: False (indicator bit set to 1)
	//  - Payload length
	uint64_t len = obj->dataBytes.size() / 2;
	set_header(header, headerFlags, len, 0, obj->messageId, obj->crc);

	// Copy only 5 bytes of header to flexrayData
	uint8_t* headerPtr = (uint8_t*)&header;
	memcpy(&flexrayData[2], headerPtr + 3, 5);

	// FlexRay Frame Payload (0-254 bytes)
	std::copy(obj->dataBytes.begin(), obj->dataBytes.end(), flexrayData.begin() + 7);

	write_packet(exporter, LINKTYPE_FLEXRAY, obj, obj->dataBytes.size() + 7, flexrayData.data(), date_offset_ns);
}

// FLEXRAY_SYNC = 30
void write(pcapng_exporter::PcapngExporter exporter, FlexRaySync* obj, uint64_t date_offset_ns) {

	uint64_t header = 0;
	uint8_t headerFlags = 0;
	std::array<uint8_t, 261> flexrayData;

	memset(&flexrayData, 0, sizeof(flexrayData));

	/// Measurement Header (1 byte)
	set_measurment_header(flexrayData[0], FlexRayPacketType::FlexRayFrame);

	/// Error Flags Information (1 byte) -> set to 0

	/// FlexRay Frame Header (5 bytes)
	//  - Header flags
	headerFlags |= 0x04; // Null Frame: False (indicator bit set to 1)
	headerFlags |= 0x02; // Sync. frame indicator bit set to 1

	/// FlexRay Frame Header (5 bytes)
	//  - Payload length
	uint64_t len = obj->dataBytes.size() / 2;
	set_header(header, headerFlags, len, obj->cycle, obj->messageId, obj->crc);

	// Copy only 5 bytes of header to flexrayData
	uint8_t* headerPtr = (uint8_t*)&header;
	memcpy(&flexrayData[2], headerPtr + 3, 5);

	// FlexRay Frame Payload (0-254 bytes)
	std::copy(obj->dataBytes.begin(), obj->dataBytes.end(), flexrayData.begin() + 7);

	write_packet(exporter, LINKTYPE_FLEXRAY, obj, obj->dataBytes.size() + 7, flexrayData.data(), date_offset_ns);
}

// FLEXRAY_CYCLE = 40
void write(pcapng_exporter::PcapngExporter exporter, FlexRayV6StartCycleEvent* obj, uint64_t date_offset_ns) {

	uint64_t header = 0;
	uint8_t headerFlags = 0;
	std::array<uint8_t, 261> flexrayData;

	memset(&flexrayData, 0, sizeof(flexrayData));

	/// Measurement Header (1 byte)
	set_measurment_header(flexrayData[0], FlexRayPacketType::FlexRayFrame);

	/// Error Flags Information (1 byte) -> set to 0

	/// FlexRay Frame Header (5 bytes)
	//  - Header flags
	headerFlags |= 0x04; // Null Frame: False (indicator bit set to 1)
	//  - Payload length
	uint64_t len = obj->dataBytes.size() / 2;
	set_header(header, headerFlags, len);

	// Copy only 5 bytes of header to flexrayData
	uint8_t* headerPtr = (uint8_t*)&header;
	memcpy(&flexrayData[2], headerPtr + 3, 5);

	// FlexRay Frame Payload (0-254 bytes)
	std::copy(obj->dataBytes.begin(), obj->dataBytes.end(), flexrayData.begin() + 7);

	write_packet(exporter, LINKTYPE_FLEXRAY, obj, obj->dataBytes.size() + 7, flexrayData.data(), date_offset_ns);
}

// FLEXRAY_MESSAGE = 41
void write(pcapng_exporter::PcapngExporter exporter, FlexRayV6Message* obj, uint64_t date_offset_ns) {

	uint64_t header = 0;
	uint8_t headerFlags = 0;
	std::array<uint8_t, 261> flexrayData;

	memset(&flexrayData, 0, sizeof(flexrayData));

	/// Measurement Header (1 byte)
	set_measurment_header(flexrayData[0], FlexRayPacketType::FlexRayFrame);

	/// Error Flags Information (1 byte) -> set to 0

	/// FlexRay Frame Header (5 bytes)
	set_header_flags(obj->frameState, headerFlags);
	uint64_t len = obj->dataBytes.size() / 2;
	set_header(header, headerFlags, len, obj->cycle, obj->frameId, obj->headerCrc);

	// Copy only 5 bytes of header to flexrayData
	uint8_t* headerPtr = (uint8_t*)&header;
	memcpy(&flexrayData[2], headerPtr + 3, 5);

	// FlexRay Frame Payload (0-254 bytes)
	std::copy(obj->dataBytes.begin(), obj->dataBytes.end(), flexrayData.begin() + 7);

	write_packet(exporter, LINKTYPE_FLEXRAY, obj, obj->dataBytes.size() + 7, flexrayData.data(), date_offset_ns);
}

// FR_ERROR = 47
void write(pcapng_exporter::PcapngExporter exporter, FlexRayVFrError* obj, uint64_t date_offset_ns) {

	uint64_t header = 0;
	uint8_t headerFlags = 0;
	std::array<uint8_t, 7> flexrayData;

	memset(&flexrayData, 0, sizeof(flexrayData));

	/// Measurement Header (1 byte)
	set_measurment_header(flexrayData[0], FlexRayPacketType::FlexRayFrame, obj->channelMask);

	/// Error Flags Information (1 byte)
	flexrayData[1] |= 0x02; // Coding error bit (CODERR) set to 1

	/// FlexRay Frame Header (5 bytes)
	//  - Header flags
	headerFlags |= 0x04; // Null Frame: False (indicator bit set to 1)
	set_header(header, headerFlags, 0, obj->cycle);

	// Copy only 5 bytes of header to flexrayData
	uint8_t* headerPtr = (uint8_t*)&header;
	memcpy(&flexrayData[2], headerPtr + 3, 5);

	/// FlexRay Frame Payload (0-254 bytes) -> no payload

	write_packet(exporter, LINKTYPE_FLEXRAY, obj, 7, flexrayData.data(), date_offset_ns);
}

// FR_STATUS = 48
void write(pcapng_exporter::PcapngExporter exporter, FlexRayVFrStatus* obj, uint64_t date_offset_ns) {

	std::array<uint8_t, 2> flexraySymbolData;

	memset(&flexraySymbolData, 0, sizeof(flexraySymbolData));

	/// Measurement Header (1 byte)
	set_measurment_header(flexraySymbolData[0], FlexRayPacketType::FlexRaySymbol, obj->channelMask);

	/// Symbol length (1 byte)
	if (obj->tag == 3) /* BUSDOCTOR */
	{
		flexraySymbolData[1] = obj->data[1] & 0xFF;
	}
	if (obj->tag == 5) /* VN-Interface */
	{
		flexraySymbolData[1] = obj->data[0] & 0xFF;
	}

	write_packet(exporter, LINKTYPE_FLEXRAY, obj, 2, flexraySymbolData.data(), date_offset_ns);
}

// FR_STARTCYCLE = 49
void write(pcapng_exporter::PcapngExporter exporter, FlexRayVFrStartCycle* obj, uint64_t date_offset_ns) {

	uint64_t header = 0;
	uint8_t headerFlags = 0;
	std::array<uint8_t, 19> flexrayData;

	memset(&flexrayData, 0, sizeof(flexrayData));

	/// Measurement Header (1 byte)
	set_measurment_header(flexrayData[0], FlexRayPacketType::FlexRayFrame, obj->channelMask);

	/// Error Flags Information (1 byte) -> set to 0

	/// FlexRay Frame Header (5 bytes)
	//  - Header flags
	headerFlags |= 0x04; // Null Frame: False (indicator bit set to 1)
	//  - Payload length
	uint64_t len = obj->dataBytes.size() / 2;
	set_header(header, headerFlags, len, obj->cycle);

	// Copy only 5 bytes of header to flexrayData
	uint8_t* headerPtr = (uint8_t*)&header;
	memcpy(&flexrayData[2], headerPtr + 3, 5);

	// FlexRay Frame Payload (0-254 bytes)
	std::copy(obj->dataBytes.begin(), obj->dataBytes.end(), flexrayData.begin() + 7);

	write_packet(exporter, LINKTYPE_FLEXRAY, obj, obj->dataBytes.size() + 7, flexrayData.data(), date_offset_ns);
}

// FR_RCVMESSAGE = 50
void write(pcapng_exporter::PcapngExporter exporter, FlexRayVFrReceiveMsg* obj, uint64_t date_offset_ns) {

	uint64_t header = 0;
	uint16_t headerCrc = 0;
	uint8_t headerFlags = 0;
	std::array<uint8_t, 261> flexrayData;

	memset(&flexrayData, 0, sizeof(flexrayData));

	/// Measurement Header (1 byte)
	set_measurment_header(flexrayData[0], FlexRayPacketType::FlexRayFrame, obj->channelMask);

	/// Error Flags Information (1 byte) -> case Error flag (error frame or invalid frame) set to 1
	if (HAS_FLAG(obj->frameFlags, 6))
	{
		flexrayData[1] |= 0x10; // FCRCERR bit set to 1
	}

	/// FlexRay Frame Header (5 bytes)
	//  - Header flags
	set_header_flags_rcv_msg(obj->frameFlags, headerFlags);
	// 	- Header CRC
	set_header_crc(obj->channelMask, obj->headerCrc1, obj->headerCrc2, headerCrc);
	//  - Payload length
	uint64_t len = obj->dataBytes.size() / 2;
	set_header(header, headerFlags, len, obj->cycle, obj->frameId, headerCrc);

	// Copy only 5 bytes of header to flexrayData
	uint8_t* headerPtr = (uint8_t*)&header;
	memcpy(&flexrayData[2], headerPtr + 3, 5);

	// FlexRay Frame Payload (0-254 bytes)
	std::copy(obj->dataBytes.begin(), obj->dataBytes.end(), flexrayData.begin() + 7);

	write_packet(exporter, LINKTYPE_FLEXRAY, obj, obj->dataBytes.size() + 7, flexrayData.data(), date_offset_ns);
}

// FR_RCVMESSAGE_EX = 66
void write(pcapng_exporter::PcapngExporter exporter, FlexRayVFrReceiveMsgEx* obj, uint64_t date_offset_ns) {

	uint64_t header = 0;
	uint16_t headerCrc = 0;
	uint8_t headerFlags = 0;
	uint8_t measurementHeader = 0;
	uint8_t errorFlagsInfo = 0;
	std::vector<uint8_t> flexrayData;

	flexrayData.clear();

	/// Measurement Header (1 byte)
	set_measurment_header(measurementHeader, FlexRayPacketType::FlexRayFrame, obj->channelMask);

	flexrayData.push_back(measurementHeader);

	/// Error Flags Information (1 byte) -> case Error flag (error frame or invalid frame) set to 1
	if (HAS_FLAG(obj->frameFlags, 6))
	{
		errorFlagsInfo |= 0x10; // FCRCERR bit set to 1
	}
	flexrayData.push_back(errorFlagsInfo);

	/// FlexRay Frame Header (5 bytes)
	//  - Header flags
	set_header_flags_rcv_msg(obj->frameFlags, headerFlags);
	// 	- Header CRC
	set_header_crc(obj->channelMask, obj->headerCrc1, obj->headerCrc2, headerCrc);
	//  - Payload length
	uint64_t len = obj->dataBytes.size() / 2;
	set_header(header, headerFlags, len, obj->cycle, obj->frameId, headerCrc);

	// Copy only 5 bytes of header to flexrayData
	uint8_t* headerPtr = (uint8_t*)&header;
	std::vector<uint8_t> headerVec(headerPtr + 3, headerPtr + 8);
	flexrayData.insert(flexrayData.end(), headerVec.begin(), headerVec.end());

	// FlexRay Frame Payload (0-254 bytes)
	flexrayData.insert(flexrayData.end(), obj->dataBytes.begin(), obj->dataBytes.end());

	write_packet(exporter, LINKTYPE_FLEXRAY, obj, obj->dataBytes.size() + 7, flexrayData.data(), date_offset_ns);
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

template<class LinErrorBase>
int write_lin_error(
	pcapng_exporter::PcapngExporter writer,
	LinErrorBase* lerr,
	std::uint8_t errors,
	uint64_t date_offset_ns)
{
	pcapng_exporter::frame_header header = generate_header(lerr, date_offset_ns);
	if (header.timestamp_resolution == 0) return -3;
	lin_frame frame = lin_frame();
	frame.errors = errors;
	writer.write_lin(header, frame);
	return 0;
}

template<class LinMessageBase>
int write_lin_message(
	pcapng_exporter::PcapngExporter writer,
	LinMessageBase* msg,
	uint64_t date_offset_ns)
{
	pcapng_exporter::frame_header header = generate_header(msg, date_offset_ns);
	if (header.timestamp_resolution == 0) return -3;
	lin_frame frame = lin_frame();
	frame.pid = msg->id;
	frame.payload_length = (std::uint8_t)(msg->data.size());
	memcpy(frame.data, &(msg->data), frame.payload_length);
	frame.checksum = msg->crc;
	writer.write_lin(header, frame);
	return 0;
}

int main(int argc, char* argv[]) {
	args::ArgumentParser parser("This tool is intended for converting BLF files to plain PCAPNG files.");
	parser.helpParams.showTerminator = false;
	parser.helpParams.proglineShowFlags = true;

	args::HelpFlag help(parser, "help", "", { 'h', "help" }, args::Options::HiddenFromUsage);
	args::ValueFlag<std::string> maparg(parser, "map-file", "Configuration file for channel mapping", { "channel-map" });

	args::Positional<std::string> inarg(parser, "infile", "Input File", args::Options::Required);
	args::Positional<std::string> outarg(parser, "outfile", "Output File", args::Options::Required);

	try
	{
		parser.ParseCLI(argc, argv);
	}
	catch (args::Help)
	{
		std::cout << parser;
		return 0;
	}
	catch (args::Error e)
	{
		std::cerr << e.what() << std::endl;
		std::cerr << parser;
		return 1;
	}

	Vector::BLF::File infile;
	infile.open(args::get(inarg));
	if (!infile.is_open()) {
		fprintf(stderr, "Unable to open: %s\n", argv[1]);
		return 1;
	}
	pcapng_exporter::PcapngExporter exporter = pcapng_exporter::PcapngExporter(args::get(outarg), maparg.Get());

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
		std::uint8_t errors = 0;
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

		case ObjectType::FLEXRAY_DATA:
			write(exporter, reinterpret_cast<FlexRayData*>(ohb), startDate_ns);
			break;

		case ObjectType::FLEXRAY_SYNC:
			write(exporter, reinterpret_cast<FlexRaySync*>(ohb), startDate_ns);
			break;

		case ObjectType::FLEXRAY_CYCLE:
			write(exporter, reinterpret_cast<FlexRayV6StartCycleEvent*>(ohb), startDate_ns);
			break;

		case ObjectType::FLEXRAY_MESSAGE:
			write(exporter, reinterpret_cast<FlexRayV6Message*>(ohb), startDate_ns);
			break;

		case ObjectType::FLEXRAY_STATUS:
			// We do not have reliable BLF file or clear documentation for this type
			break;

		case ObjectType::FR_ERROR:
			write(exporter, reinterpret_cast<FlexRayVFrError*>(ohb), startDate_ns);
			break;

		case ObjectType::FR_STATUS:
			write(exporter, reinterpret_cast<FlexRayVFrStatus*>(ohb), startDate_ns);
			break;

		case ObjectType::FR_STARTCYCLE:
			write(exporter, reinterpret_cast<FlexRayVFrStartCycle*>(ohb), startDate_ns);
			break;

		case ObjectType::FR_RCVMESSAGE:
			write(exporter, reinterpret_cast<FlexRayVFrReceiveMsg*>(ohb), startDate_ns);
			break;

		case ObjectType::FR_RCVMESSAGE_EX:
			write(exporter, reinterpret_cast<FlexRayVFrReceiveMsgEx*>(ohb), startDate_ns);
			break;

		case ObjectType::APP_TEXT:
			configure_channels(&exporter, reinterpret_cast<AppText*>(ohb));
			break;

		case ObjectType::LIN_MESSAGE:
			write_lin_message(exporter, reinterpret_cast<LinMessage*>(ohb), startDate_ns);
			break;

		case ObjectType::LIN_MESSAGE2:
			write_lin_message(exporter, reinterpret_cast<LinMessage2*>(ohb), startDate_ns);
			break;

		case ObjectType::LIN_CRC_ERROR:
			errors = LIN_ERROR_CHECKSUM;
			write_lin_error(exporter, reinterpret_cast<LinCrcError*>(ohb), errors, startDate_ns);
			break;

		case ObjectType::LIN_CRC_ERROR2:
			errors = LIN_ERROR_CHECKSUM;
			write_lin_error(exporter, reinterpret_cast<LinCrcError2*>(ohb), errors, startDate_ns);
			break;

		case ObjectType::LIN_RCV_ERROR:
			errors = LIN_ERROR_FRAMING;
			write_lin_error(exporter, reinterpret_cast<LinReceiveError*>(ohb), errors, startDate_ns);
			break;

		case ObjectType::LIN_RCV_ERROR2:
			errors = LIN_ERROR_FRAMING;
			write_lin_error(exporter, reinterpret_cast<LinReceiveError2*>(ohb), errors, startDate_ns);
			break;

		case ObjectType::LIN_SLV_TIMEOUT:
			errors = LIN_ERROR_NOSLAVE;
			write_lin_error(exporter, reinterpret_cast<LinSlaveTimeout*>(ohb), errors, startDate_ns);
			break;

		case ObjectType::LIN_SND_ERROR:
			errors = LIN_ERROR_FRAMING;
			write_lin_error(exporter, reinterpret_cast<LinSendError*>(ohb), errors, startDate_ns);
			break;

		case ObjectType::LIN_SND_ERROR2:
			errors = LIN_ERROR_FRAMING;
			write_lin_error(exporter, reinterpret_cast<LinSendError2*>(ohb), errors, startDate_ns);
			break;

		case ObjectType::LIN_SYN_ERROR:
			errors = LIN_ERROR_FRAMING;
			write_lin_error(exporter, reinterpret_cast<LinSyncError*>(ohb), errors, startDate_ns);
			break;

		case ObjectType::LIN_SYN_ERROR2:
			errors = LIN_ERROR_FRAMING;
			write_lin_error(exporter, reinterpret_cast<LinSyncError2*>(ohb), errors, startDate_ns);
			break;

		default:
#ifdef DEBUG
			std::cerr << (std::uint32_t)(ohb->objectType) << " is not implemented." << std::endl;
#endif
			break;

		}

		/* delete object */
		delete ohb;
	}
	infile.close();
	return 0;
}
