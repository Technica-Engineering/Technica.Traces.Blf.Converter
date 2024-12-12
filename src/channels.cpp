/*
  Copyright (c) 2020 Technica Engineering GmbH
  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/

#include "channels.hpp"
#include <tinyxml2.h>
#include <sstream>
#include <map>
#include <pcapng_exporter/linktype.h>

using namespace Vector::BLF;

std::vector<std::string> split(const std::string& s, char delim) {
	std::vector<std::string> result;
	std::stringstream ss(s);
	std::string item;

	while (getline(ss, item, delim)) {
		result.push_back(item);
	}

	return result;
}

std::optional<uint16_t> bus_type_to_linklayer(uint32_t bus_type) {
	switch (bus_type)
	{
	case 0x01: return LINKTYPE_CAN;
	case 0x05: return LINKTYPE_LIN;
	case 0x07: return LINKTYPE_FLEXRAY;
	case 0x0B: return LINKTYPE_ETHERNET;
	default: return std::nullopt;
	}
}

std::optional<uint16_t> bus_name_to_linklayer(std::string bus_type) {
	if (bus_type == "CAN") return LINKTYPE_CAN;
	if (bus_type == "LIN") return LINKTYPE_LIN;
	if (bus_type == "FlexRay") return LINKTYPE_FLEXRAY;
	if (bus_type == "Ethernet") return LINKTYPE_ETHERNET;
	return std::nullopt;
}

void configure_db_channel(pcapng_exporter::PcapngExporter* exporter, AppText* obj) {

	auto channel_id = (obj->reservedAppText1 >> 8) & 0xFF;
	auto channel_link = bus_type_to_linklayer((obj->reservedAppText1 >> 16) & 0xFF);
	auto db_channels = split(obj->text, ';');
	if (db_channels.size() < 2 || !channel_link.has_value()) {
		// Invalid mapping
		return;
	}
	pcapng_exporter::channel_mapping mapping;
	mapping.when.chl_id = channel_id;
	mapping.when.chl_link = channel_link;
	mapping.change.inf_name = db_channels[1];
	exporter->mappings.push_back(mapping);

}


void configure_xml_channel(pcapng_exporter::PcapngExporter* exporter, tinyxml2::XMLElement* channel) {

	auto channel_type = std::string(channel->Attribute("type") ? channel->Attribute("type") : "");
	auto channel_id = channel->IntAttribute("number");
	auto channel_name = std::string(channel->Attribute("network") ? channel->Attribute("network") : "");

	if (!channel_type.empty() && !channel_name.empty()) {
		pcapng_exporter::channel_mapping mapping;
		mapping.when.chl_id = channel_id;
		mapping.when.chl_link = bus_name_to_linklayer(channel_type);
		mapping.change.inf_name = channel_name;
		exporter->mappings.push_back(mapping);
	}

	auto channel_properties = channel->FirstChildElement("channel_properties");
	if (!channel_properties) {
		return;
	}
	for (auto elist = channel_properties->FirstChildElement("elist"); elist != NULL; elist = elist->NextSiblingElement("elist"))
	{
		if (!elist->Attribute("name", "ports")) {
			continue;
		}
		for (auto port = elist->FirstChildElement("eli"); port != NULL; port = port->NextSiblingElement("eli"))
		{
			if (!port->Attribute("name", "port")) {
				continue;
			}
			pcapng_exporter::channel_mapping mapping;
			mapping.when.chl_link = bus_name_to_linklayer(channel_type);

			for (const auto& prop : split(port->GetText(), ';')) {
				auto pair = split(prop, '=');
				auto key = pair.front();
				auto value = pair.back();

				if (key == "name") {
					mapping.change.inf_name = channel_name + "::" + value;
				}
				if (key == "hwchannel") {
					auto hwchannel = std::stoi(value);
					// We only have one channel id field, so we concat both hwchannel and channel_id
					mapping.when.chl_id = hwchannel * 100000 + channel_id;
				}
			}

			if (mapping.change.inf_name && mapping.when.chl_id) {
				exporter->mappings.push_back(mapping);
			}
		}
	}
}

std::map<int, std::stringstream> xml_channel_mapping;
void configure_xml_channels(pcapng_exporter::PcapngExporter* exporter, AppText* obj) {
	auto metadata_id = obj->reservedAppText1 >> 24;
	auto remaining_len = obj->reservedAppText1 & 0xffffff;
	auto part_len = obj->text.size();
	if (!xml_channel_mapping.count(metadata_id)) {
		xml_channel_mapping.insert_or_assign(metadata_id, std::stringstream());
	}
	std::stringstream& xml_stream = xml_channel_mapping[metadata_id];
	xml_stream << obj->text;
	if (obj->textLength != remaining_len) {
		// More text is pending
		return;
	}
	tinyxml2::XMLDocument doc;
	if (doc.Parse(xml_stream.str().c_str()) != tinyxml2::XMLError::XML_SUCCESS) {
		// Invalid XML
		return;
	}
	auto channels = doc.FirstChildElement("channels");
	if (!channels) {
		// Not a channels XML
		return;
	}
	for (auto channel = channels->FirstChildElement("channel"); channel != NULL; channel = channel->NextSiblingElement("channel"))
	{
		configure_xml_channel(exporter, channel);
	}
}

void configure_channels(pcapng_exporter::PcapngExporter* exporter, AppText* obj) {
	if (obj->source == AppText::Source::DbChannelInfo) {
		configure_db_channel(exporter, obj);
	}
	if (obj->source == AppText::Source::MetaData) {
		configure_xml_channels(exporter, obj);
	}
}