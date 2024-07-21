#!/bin/bash
# Main entry of build script.
# Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
set -e

export CROSS_COMPILE=mipsel-linux-
export KDIR=/home/paul/output/cinnado_d1_t31l/build/linux-418473627666ad72bf030394311f247740b9ebe5

CROOT=$(pwd)

WIFI_DRIVER_DIR=$CROOT/driver

usage(){
    echo -e "\033[32m  build.sh: [options]
        -h: help
        -l: build 3881 liteos driver
        -m: build 3881 linux driver
        -v: build sdk
        -c: clean

  build 3881 liteos version driver driver:
  ./build.sh -l

  build non IoT linux version driver driver:
  ./build.sh -m \033[0m"
}

while [ $# -ge 1 ] ; do
        case "$1" in
		-l) BUILD_SELECT=liteos_driver; shift 1;;
		-m) BUILD_SELECT=linux_driver; shift 1;;
		-c) BUILD_SELECT=clean; shift 1;;
		-R) BUILD_SELECT=build_sdk; shift 1;;
		-v) if [ "$2" == "" ];then echo "parameter err"; usage; exit 1; fi; VERSION=$2; if [ "$3" != "" ];then KERNEL_VER=$3; shift 3; else shift 2; fi;;
		-h) usage;  exit 1;break;;
                *) echo "unknown parameter $1" ; usage; exit 1 ; break;;
        esac
done

creat_build_logs() {
	cd $CROOT
	if [ ! -d $CROOT/build/build_tmp/logs/ ]; then
		mkdir -p $CROOT/build/build_tmp/logs;
		echo "mkdir logs"
	fi
}

if [ "$BUILD_SELECT" == "linux_driver" ];then
	make -f Makefile clean; \
	creat_build_logs;
	make -f Makefile all 2>&1 |tee $CROOT/build/build_tmp/logs/build_linux.log; \
elif [ "$BUILD_SELECT" == "liteos_driver" ];then
        if [ "$CFG_KERNEL_SMP" == "y" ];then
                sed -i 's/CFG_KERNEL_SMP = n/CFG_KERNEL_SMP = y/g' ${WIFI_DRIVER_DIR}/env_config.mk;
        fi
	sed -i 's/CFG_LITEOS = n/CFG_LITEOS = y/g' ${WIFI_DRIVER_DIR}/env_config.mk; \
	make -f Makefile_liteos clean; \
	make -f Makefile_liteos sample_clean; \
	creat_build_logs;
	make -f Makefile_liteos -j16 -k 2>&1 |tee $CROOT/build/build_tmp/logs/build_liteos.log; \
	make -f Makefile_liteos sample; \
	sed -i 's/CFG_LITEOS = y/CFG_LITEOS = n/g' ${WIFI_DRIVER_DIR}/env_config.mk; \
        if [ "$CFG_KERNEL_SMP" == "y" ];then
                sed -i 's/CFG_KERNEL_SMP = y/CFG_KERNEL_SMP = n/g' ${WIFI_DRIVER_DIR}/env_config.mk;
        fi
elif [ "$BUILD_SELECT" == "clean" ];then
	make -f Makefile clean; \
	sed -i 's/CFG_LITEOS = n/CFG_LITEOS = y/g' ${WIFI_DRIVER_DIR}/env_config.mk; \
	make -f Makefile_liteos clean; \
	sed -i 's/CFG_LITEOS = y/CFG_LITEOS = n/g' ${WIFI_DRIVER_DIR}/env_config.mk; \
elif [ "$BUILD_SELECT" == "build_sdk" ];then
    ./build/sdk/build_sdk.sh $VERSION;
fi
