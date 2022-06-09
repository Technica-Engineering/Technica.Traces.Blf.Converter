/*
  Copyright (c) 2020 Technica Engineering GmbH
  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/
#ifndef _APP_CHANNELS_H
#define _APP_CHANNELS_H

#include <Vector/BLF.h>
#include <pcapng_exporter/pcapng_exporter.hpp>

void configure_channels(pcapng_exporter::PcapngExporter* exporter, Vector::BLF::AppText* obj);

#endif