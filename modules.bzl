# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2022 The Android Open Source Project

"""
This module contains a full list of kernel modules
 compiled by GKI.
"""

_COMMON_GKI_MODULES_LIST = [
    # keep sorted
    "drivers/bluetooth/btbcm.ko",
    "drivers/bluetooth/btintel.ko",
    "drivers/bluetooth/btrtl.ko",
    "drivers/bluetooth/btusb.ko",
    "drivers/bluetooth/hci_uart.ko",
    "drivers/platform/x86/socwatch/socwatch2_15.ko",
    "net/bluetooth/bluetooth.ko",
    "net/bluetooth/hidp/hidp.ko",
    "net/bluetooth/rfcomm/rfcomm.ko",
    "net/mac80211/mac80211.ko",
    "net/wireless/cfg80211.ko",
]

# Deprecated - Use `get_gki_modules_list` function instead.
COMMON_GKI_MODULES_LIST = _COMMON_GKI_MODULES_LIST

_ARM_GKI_MODULES_LIST = [
    # keep sorted
    "drivers/ptp/ptp_kvm.ko",
]

_ARM64_GKI_MODULES_LIST = [
    # keep sorted
    "arch/arm64/geniezone/gzvm.ko",
    "drivers/char/hw_random/cctrng.ko",
    "drivers/misc/open-dice.ko",
    "drivers/ptp/ptp_kvm.ko",
]

_X86_GKI_MODULES_LIST = [
    # keep sorted
    "drivers/ptp/ptp_kvm.ko",
]

_X86_64_GKI_MODULES_LIST = [
    # keep sorted
    "crypto/michael_mic.ko",
    "drivers/accel/ivpu/intel_vpu.ko",
    "drivers/bcma/bcma.ko",
    "drivers/bluetooth/ath3k.ko",
    "drivers/char/tpm/tpm_atmel.ko",
    "drivers/char/tpm/tpm_crb.ko",
    "drivers/char/tpm/tpm_i2c_atmel.ko",
    "drivers/char/tpm/tpm_i2c_infineon.ko",
    "drivers/char/tpm/tpm_i2c_nuvoton.ko",
    "drivers/char/tpm/tpm_infineon.ko",
    "drivers/char/tpm/tpm.ko",
    "drivers/char/tpm/tpm_nsc.ko",
    "drivers/char/tpm/tpm_tis_core.ko",
    "drivers/char/tpm/tpm_tis.ko",
    "drivers/firmware/efi/efibc.ko",
    "drivers/firmware/efi/efi-pstore.ko",
    "drivers/gpio/gpio-arizona.ko",
    "drivers/hid/hid-elo.ko",
    "drivers/hid/hid-ntrig.ko",
    "drivers/hid/hid-sensor-hub.ko",
    "drivers/hid/hid-xinmo.ko",
    "drivers/hwmon/dell-smm-hwmon.ko",
    "drivers/hwmon/sch5627.ko",
    "drivers/hwmon/sch5636.ko",
    "drivers/hwmon/sch56xx-common.ko",
    "drivers/iio/accel/bma180.ko",
    "drivers/iio/accel/hid-sensor-accel-3d.ko",
    "drivers/iio/adc/mcp320x.ko",
    "drivers/iio/adc/nau7802.ko",
    "drivers/iio/common/hid-sensors/hid-sensor-iio-common.ko",
    "drivers/iio/common/hid-sensors/hid-sensor-trigger.ko",
    "drivers/iio/gyro/hid-sensor-gyro-3d.ko",
    "drivers/iio/light/cm36651.ko",
    "drivers/iio/light/hid-sensor-als.ko",
    "drivers/iio/light/jsa1212.ko",
    "drivers/iio/magnetometer/ak8975.ko",
    "drivers/iio/magnetometer/hid-sensor-magn-3d.ko",
    "drivers/iio/orientation/hid-sensor-incl-3d.ko",
    "drivers/iio/temperature/tmp006.ko",
    "drivers/input/touchscreen/cyttsp4_core.ko",
    "drivers/input/touchscreen/cyttsp4_i2c.ko",
    "drivers/input/touchscreen/cyttsp4_spi.ko",
    "drivers/input/touchscreen/cyttsp_i2c_common.ko",
    "drivers/input/touchscreen/sur40.ko",
    "drivers/input/touchscreen/zforce_ts.ko",
    "drivers/md/bcache/bcache.ko",
    "drivers/media/tuners/qm1d1b0004.ko",
    "drivers/media/tuners/tda18250.ko",
    "drivers/mfd/arizona-i2c.ko",
    "drivers/mfd/arizona.ko",
    "drivers/misc/eeprom/eeprom_93cx6.ko",
    "drivers/misc/mei/hdcp/mei_hdcp.ko",
    "drivers/misc/mei/mei-gsc.ko",
    "drivers/misc/mei/mei.ko",
    "drivers/misc/mei/mei-me.ko",
    "drivers/misc/mei/mei-txe.ko",
    "drivers/misc/mei/pxp/mei_pxp.ko",
    "drivers/net/ethernet/stmicro/stmmac/dwmac-generic.ko",
    "drivers/net/ethernet/stmicro/stmmac/dwmac-intel.ko",
    "drivers/net/ethernet/stmicro/stmmac/stmmac.ko",
    "drivers/net/ethernet/stmicro/stmmac/stmmac-platform.ko",
    "drivers/net/mdio/mdio-bitbang.ko",
    "drivers/net/nlmon.ko",
    "drivers/net/pcs/pcs_xpcs.ko",
    "drivers/net/usb/huawei_cdc_ncm.ko",
    "drivers/net/usb/sr9700.ko",
    "drivers/net/wireless/intel/iwlwifi/dvm/iwldvm.ko",
    "drivers/net/wireless/intel/iwlwifi/iwlwifi.ko",
    "drivers/net/wireless/intel/iwlwifi/mvm/iwlmvm.ko",
    "drivers/pci/controller/vmd.ko",
    "drivers/pinctrl/intel/pinctrl-cannonlake.ko",
    "drivers/pinctrl/intel/pinctrl-icelake.ko",
    "drivers/pinctrl/intel/pinctrl-jasperlake.ko",
    "drivers/pinctrl/intel/pinctrl-tigerlake.ko",
    "drivers/power/supply/generic-adc-battery.ko",
    "drivers/power/supply/isp1704_charger.ko",
    "drivers/staging/gdm724x/gdmtty.ko",
    "drivers/staging/gdm724x/gdmulte.ko",
    "drivers/thermal/intel/intel_soc_dts_thermal.ko",
    "drivers/usb/class/cdc-wdm.ko",
    "drivers/usb/class/usblp.ko",
    "drivers/video/backlight/bd6107.ko",
    "drivers/video/backlight/gpio_backlight.ko",
    "drivers/video/backlight/lcd.ko",
    "drivers/video/backlight/lm3630a_bl.ko",
    "drivers/video/backlight/lv5207lp.ko",
    "drivers/video/backlight/platform_lcd.ko",
    "lib/crc64.ko",
    "lib/math/cordic.ko",
    "net/bluetooth/bnep/bnep.ko",
    "net/netfilter/xt_AUDIT.ko",
    "net/rfkill/rfkill-gpio.ko",
    "net/wireless/lib80211.ko",
    "sound/core/oss/snd-mixer-oss.ko",
    "sound/core/oss/snd-pcm-oss.ko",
    "sound/core/seq/snd-seq.ko",
    "sound/core/seq/snd-seq-midi-event.ko",
    "sound/core/seq/snd-seq-midi.ko",
    "sound/core/snd-compress.ko",
    "sound/core/snd-ctl-led.ko",
    "sound/drivers/snd-dummy.ko",
    "sound/hda/ext/snd-hda-ext-core.ko",
    "sound/hda/snd-hda-core.ko",
    "sound/hda/snd-intel-dspcfg.ko",
    "sound/hda/snd-intel-sdw-acpi.ko",
    "sound/pci/hda/snd-hda-codec-generic.ko",
    "sound/pci/hda/snd-hda-codec-hdmi.ko",
    "sound/pci/hda/snd-hda-codec.ko",
    "sound/pci/hda/snd-hda-codec-realtek.ko",
    "sound/pci/hda/snd-hda-intel.ko",
    "sound/soc/codecs/snd-soc-dmic.ko",
    "sound/soc/codecs/snd-soc-hdac-hda.ko",
    "sound/soc/codecs/snd-soc-hdac-hdmi.ko",
    "sound/soc/intel/atom/snd-soc-sst-atom-hifi2-platform.ko",
    "sound/soc/intel/atom/sst/snd-intel-sst-acpi.ko",
    "sound/soc/intel/atom/sst/snd-intel-sst-core.ko",
    "sound/soc/intel/boards/snd-soc-intel-hda-dsp-common.ko",
    "sound/soc/intel/boards/snd-soc-skl_hda_dsp.ko",
    "sound/soc/intel/common/snd-soc-acpi-intel-match.ko",
    "sound/soc/intel/common/snd-soc-sst-dsp.ko",
    "sound/soc/intel/common/snd-soc-sst-ipc.ko",
    "sound/soc/intel/skylake/snd-soc-skl.ko",
    "sound/soc/snd-soc-acpi.ko",
    "sound/soc/snd-soc-core.ko",
    "sound/soc/sof/intel/snd-sof-acpi-intel-bdw.ko",
    "sound/soc/sof/intel/snd-sof-acpi-intel-byt.ko",
    "sound/soc/sof/intel/snd-sof-intel-atom.ko",
    "sound/soc/sof/intel/snd-sof-intel-hda-common.ko",
    "sound/soc/sof/intel/snd-sof-intel-hda.ko",
    "sound/soc/sof/intel/snd-sof-intel-hda-mlink.ko",
    "sound/soc/sof/intel/snd-sof-pci-intel-apl.ko",
    "sound/soc/sof/intel/snd-sof-pci-intel-cnl.ko",
    "sound/soc/sof/intel/snd-sof-pci-intel-icl.ko",
    "sound/soc/sof/intel/snd-sof-pci-intel-lnl.ko",
    "sound/soc/sof/intel/snd-sof-pci-intel-mtl.ko",
    "sound/soc/sof/intel/snd-sof-pci-intel-skl.ko",
    "sound/soc/sof/intel/snd-sof-pci-intel-tgl.ko",
    "sound/soc/sof/intel/snd-sof-pci-intel-tng.ko",
    "sound/soc/sof/snd-sof-acpi.ko",
    "sound/soc/sof/snd-sof.ko",
    "sound/soc/sof/snd-sof-pci.ko",
    "sound/soc/sof/snd-sof-probes.ko",
    "sound/soc/sof/snd-sof-utils.ko",
    "sound/soc/sof/xtensa/snd-sof-xtensa-dsp.ko",
    "sound/usb/btusb/btusb_sco_snd_card.ko",
    "sound/usb/hiface/snd-usb-hiface.ko",
]

# buildifier: disable=unnamed-macro
def get_gki_modules_list(arch = None):
    """ Provides the list of GKI modules.

    Args:
      arch: One of [arm, arm64, i386, x86_64].

    Returns:
      The list of GKI modules for the given |arch|.
    """
    gki_modules_list = [] + _COMMON_GKI_MODULES_LIST
    if arch == "arm":
        gki_modules_list += _ARM_GKI_MODULES_LIST
    elif arch == "arm64":
        gki_modules_list += _ARM64_GKI_MODULES_LIST
    elif arch == "i386":
        gki_modules_list += _X86_GKI_MODULES_LIST
    elif arch == "x86_64":
        gki_modules_list += _X86_64_GKI_MODULES_LIST
    else:
        fail("{}: arch {} not supported. Use one of [arm, arm64, i386, x86_64]".format(
            str(native.package_relative_label(":x")).removesuffix(":x"),
            arch,
        ))

    return gki_modules_list

_KUNIT_FRAMEWORK_MODULES = [
]

# Common Kunit test modules
_KUNIT_COMMON_MODULES_LIST = [
    # keep sorted
]

# KUnit test module for arm64 only
_KUNIT_CLK_MODULES_LIST = [
    "drivers/clk/clk-gate_test.ko",
    "drivers/clk/clk_test.ko",
]

# buildifier: disable=unnamed-macro
def get_kunit_modules_list(arch = None):
    """ Provides the list of GKI modules.

    Args:
      arch: One of [arm, arm64, i386, x86_64].

    Returns:
      The list of KUnit modules for the given |arch|.
    """
    kunit_modules_list = _KUNIT_FRAMEWORK_MODULES + _KUNIT_COMMON_MODULES_LIST
    if arch == "arm":
        kunit_modules_list += _KUNIT_CLK_MODULES_LIST
    elif arch == "arm64":
        kunit_modules_list += _KUNIT_CLK_MODULES_LIST
    elif arch == "i386":
        kunit_modules_list += []
    elif arch == "x86_64":
        kunit_modules_list += []
    else:
        fail("{}: arch {} not supported. Use one of [arm, arm64, i386, x86_64]".format(
            str(native.package_relative_label(":x")).removesuffix(":x"),
            arch,
        ))

    return kunit_modules_list

_COMMON_UNPROTECTED_MODULES_LIST = [
    "drivers/block/zram/zram.ko",
    "kernel/kheaders.ko",
    "mm/zsmalloc.ko",
]

# buildifier: disable=unnamed-macro
def get_gki_protected_modules_list(arch = None):
    all_gki_modules = get_gki_modules_list(arch) + get_kunit_modules_list(arch)
    unprotected_modules = _COMMON_UNPROTECTED_MODULES_LIST
    protected_modules = [mod for mod in all_gki_modules if mod not in unprotected_modules]
    return protected_modules
