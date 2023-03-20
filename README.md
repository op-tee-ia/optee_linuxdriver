# OP-TEE Linux Driver

# Description
The optee_linuxdriver git, containing the source code for the TEE driver 
module in Linux.
It is distributed under the GPLv2 open-source license.

In this git, the modules to build are tee.ko and optee.ko.
Thet allow communication between the Rich OS Client Application (unsecure
world), the Trusted OS (secure world) and the tee-supplicant (unsecure
world) which is a daemon serving the Trusted OS in secure world with
miscellaneous features, such as file system access.

## License
The software is provided under the
[GPL-2.0](http://opensource.org/licenses/GPL-2.0) license.

## Platforms supported
The driver software has been tested based on:

- IKGT hypervisor
- QEMU/KVM hypervisor

## Get and build the software

### Get the Linux kernel (from www.kernel.org or Linux distribution like Ubuntu)
	$ cd $HOME
	$ mkdir devel
	$ cd devel
	$ mkdir linux
	$ cd linux: Put Linux kernel or header files here

### Download the driver source code and replace original tee driver
	$ cd $HOME/devel/linux/drivers
	$ rm -fr tee
	$ git clone https://github.com/op-tee-ia/optee_linuxdriver.git
	$ mv optee_linuxdriver tee

### Config and Build
	$ cd $HOME/devel/linux
	$ make menuconfig
    "Device Drivers" --> "TEE Drivers" --> Select either "OP-TEE on top of IKGT hypervisor"
    or "OP-TEE on top of QEMU hypervisor" based on the hypervisor you are using
	$ make M=drivers/tee
