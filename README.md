# PAMO
The repository containing PAMO source code based on Suricata.

## Installation
Here are the steps to compile PAMO.

### Dependencies

WORK IN PROGRESS: We're still cleaning the steps, stay tuned ;)

#### DPDK

Download and build DPDK with:

```bash
#!/bin/bash
package_root=$(pwd)
package_name="DPDK"
dest_dir=dist
repo=https:#github.com/DPDK/dpdk.git
repo_version=22.11-dut
repo_hash=v22.11
repo_dirname=dpdk-$repo_version
build_dir=build

git clone $repo $repo_dirname
cd $repo_dirname
export RTE_TARGET=x86_64-native-linuxapp-gcc
git checkout $repo_hash
mkdir $dest_dir
mkdir $build_dir
arch=native
args="\"-march=$arch -O3\""
disabled_drivers=regex/cn9k,raw/*,compress/*,baseband/*,crypto/*,dma/*,event/*,ml/*,net/mlx4
meson setup \
    -Dbuildtype=debugoptimized -Dc_args=-march=$arch \
    -Dcpp_args=-march=$arch -Ddisable_drivers=$disabled_drivers \
    -Dtests=false \
    --prefix $PWD/$dest_dir $build_dir .
cd $build_dir
ninja -j 16 install
```

#### DOCA

Altough we do use the RegEx engine from DPDK, you'll need DOCA to set your BF2 to DOCA 2.5 and enable the regex use from the host.

Install DOCA with:

```bash
export DOCA_URL="https://linux.mellanox.com/public/repo/doca/2.5.0/ubuntu22.04/x86_64/"
curl https://linux.mellanox.com/public/repo/doca/GPG-KEY-Mellanox.pub | gpg --dearmor > /etc/apt/trusted.gpg.d/GPG-KEY-Mellanox.pub
echo "deb [signed-by=/etc/apt/trusted.gpg.d/GPG-KEY-Mellanox.pub] $DOCA_URL ./" |
sudo tee /etc/apt/sources.list.d/doca.list
# Update and install required packages
sudo apt-get update
sudo apt-get -y install doca-all doca-networking
```

#### Suricata dependencies

```bash
#!/bin/bash
if $(dpkg -s cbindgen > /dev/null); then
    echo "Removing the dpkg cbindgen package"
    sudo apt remove cbindgen
fi
sudo apt install -q libyaml-dev rustc cargo libhyperscan-dev bear libcap-ng-dev libmagic-dev libmagic-dev liblz4-dev libnet1-dev \
libisal-dev libbpf-dev libibverbs-dev rdma-core #dependencies for mellanox cards

cargo install --version 0.26.0 cbindgen
python3 -m pip -q install numpy matplotlib pandas pyyaml
```

### PAMO

You are now ready to compile PAMO:

```bash
#!/bin/bash
package_root=$(pwd)
package_name="suricata"
dest_dir=dist
repo_dirname=.
skip_build="false"
dpdk_env=...
if [ $? -ne 0 ]; then
    echo "Error while resolving depency: $dpdk_env"
    exit 1
fi
source $dpdk_env
if [ -d $repo_dirname ]; then
    #Ask the user if it wants to delete the existing repo
    echo "The package $package_name:$repo_version already exists."
    read -p "Delete ? (y/n) " yn
    if [ "$yn" = "y" ]; then
        echo "Deleting..."
        rm -rf $repo_dirname
    else
        echo "Skipping build step..."
        skip_build="true"
    fi
fi
if [ "$skip_build" = "false" ]; then
    cd $repo_dirname
    ./scripts/bundle.sh
    ./autogen.sh
    CFLAGS="-O3" ./configure --prefix $(pwd)/$dest_dir --enable-dpdk
    make -j 24 install
    make install-conf
fi
cd $package_root
./gen_env.sh $repo_dirname $dest_dir $repo_version
env_file=$package_root/env-$repo_version.sh
#We add dpdk as a dependency in the env file
cat $dpdk_env > /tmp/env
cat $env_file >> /tmp/env
mv /tmp/env $env_file
source $env_file
```

## Useage

### Configuration

PAMO only extends suricata config file. A sample with PAMO variables is given in `pamo.conf.yaml`

### Running

```bash
RULES_PATH=RULES_FILES
suricata -c pamo.conf.yml --dpdk -l $log_dir  -S ${RULES_PATH} -v
```

## RXPBench
RXPBench, the benchmarking tool for the RXP engine is available at [https:#github.com/UCLouvain-ENSG/PAMO-RXPBench/](https:#github.com/UCLouvain-ENSG/PAMO-RXPBench/).

## Trace acceleration
Scripts to split and rewrite a trace as done in the paper are available at [https:#github.com/uclouvain-ensg/pamo-traces](https:#github.com/uclouvain-ensg/pamo-traces).
