## @file
# List of Core Components.
#
# Copyright (c) 1985 - 2022, AMI. All rights reserved.<BR>
# Subject to AMI licensing agreement.
##

  UsbNetworkPkg/NetworkCommon/NetworkCommon.inf

!if gUsbNetworkPkgTokenSpaceGuid.UsbCdcEcmSupport
  UsbNetworkPkg/UsbCdcEcm/UsbCdcEcm.inf
!endif

!if gUsbNetworkPkgTokenSpaceGuid.UsbCdcNcmSupport
  UsbNetworkPkg/UsbCdcNcm/UsbCdcNcm.inf
!endif

!if gUsbNetworkPkgTokenSpaceGuid.UsbRndisSupport
  UsbNetworkPkg/UsbRndis/UsbRndis.inf
!endif
