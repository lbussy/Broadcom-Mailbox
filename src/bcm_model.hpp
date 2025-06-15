#ifndef BCM_CHIP_HPP
#define BCM_CHIP_HPP
#pragma once

#include <string_view>

enum class BCMChip : int {
  BCM_HOST_PROCESSOR_BCM2835 = 0, // BCM2835 (RPi1)
  BCM_HOST_PROCESSOR_BCM2836 = 1, // BCM2836 (RPi2)
  BCM_HOST_PROCESSOR_BCM2837 = 2, // BCM2837 (RPi3)
  BCM_HOST_PROCESSOR_BCM2711 = 3, // BCM2711 (RPi4)
};

constexpr std::string_view to_string(BCMChip chip) noexcept {
    switch (chip) {
      case BCMChip::BCM_HOST_PROCESSOR_BCM2835: return "BCM2835";
      case BCMChip::BCM_HOST_PROCESSOR_BCM2836: return "BCM2836";
      case BCMChip::BCM_HOST_PROCESSOR_BCM2837: return "BCM2837";
      case BCMChip::BCM_HOST_PROCESSOR_BCM2711: return "BCM2711";
    }
    return "Unknown";
}

#endif // BCM_CHIP_HPP
