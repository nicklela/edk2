## @file
# Global switches enable/disable project features.
#
# Copyright (c) 1985 - 2022, AMI. All rights reserved.<BR>
# Subject to AMI licensing agreement.
##

[Defines]
!if "IA32" in $(ARCH) && "X64" in $(ARCH)
  DEFINE PEI=IA32
  DEFINE DXE=X64
!else
  DEFINE PEI=COMMON
  DEFINE DXE=COMMON
!endif

[Packages]
  UsbNetworkPkg/UsbNetworkPkg.dec

[PcdsFeatureFlag]
  gUsbNetworkPkgTokenSpaceGuid.UsbCdcEcmSupport|FALSE
  gUsbNetworkPkgTokenSpaceGuid.UsbCdcNcmSupport|FALSE
  gUsbNetworkPkgTokenSpaceGuid.UsbRndisSupport|TRUE
