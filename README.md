# OP-TEE Linux Driver

The optee_linuxdriver git, containing the source code for the TEE driver 
module in Linux.
It is distributed under the GPLv2 open-source license.

In this git, the module to build is optee.ko.
It allows communication between the Rich OS Client Application (unsecure
world), the Trusted OS (secure world) and the tee-supplicant (unsecure
world) which is a daemon serving the Trusted OS in secure world with
miscellaneous features, such as file system access.
