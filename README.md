# PAMO
The repository containing PAMO source code based on Suricata.

## Installation
Here are the steps to compile PAMO.

### Dependencies

All examples are taken for Ubuntu (Server) 22.04.

We assume you start in this checked out repository.

#### DPDK

Download and build DPDK with:

```bash
package_root=$(pwd)
package_name="DPDK"
dest_dir=dist
repo=https://github.com/DPDK/dpdk.git
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
cd ..
echo "export DPDK_PATH=$package_root/$repo_dir_name/$dest_dir" >> env.rc
echo "export LD_LIBRARY_PATH=$package_root/$repo_dir_name/$dest_dir/lib/x86_64-linux-gnu:"'$LD_LIBRARY_PATH' >> env.rc
echo "export LD_LIBRARY_PATH=$package_root/$repo_dir_name/$dest_dir/lib:"'$LD_LIBRARY_PATH' >> env.rc
echo "export PKG_CONFIG_PATH=$package_root/$repo_dir_name/$dest_dir/lib/x86_64-linux-gnu/pkgconfig:"'$PKG_CONFIG_PATH' >> env.rc
mv env.rc ..
cd ..
```

#### DOCA

Altough we do use the RegEx engine from DPDK, you'll need DOCA to set your BF2 to DOCA 2.5 and enable the regex use from the host.

Install DOCA with (beware of the ubuntu22.04 in the first line, you may change that):

```bash
export DOCA_URL="https://linux.mellanox.com/public/repo/doca/2.5.0/ubuntu22.04/x86_64/"
curl https://linux.mellanox.com/public/repo/doca/GPG-KEY-Mellanox.pub | gpg --dearmor > /etc/apt/trusted.gpg.d/GPG-KEY-Mellanox.pub
echo "deb [signed-by=/etc/apt/trusted.gpg.d/GPG-KEY-Mellanox.pub] $DOCA_URL ./" | sudo tee /etc/apt/sources.list.d/doca.list
# Update and install required packages
sudo apt-get update
sudo apt-get -y install doca-all doca-networking
```

#### Suricata dependencies

Suricata uses Rust, we used 1.90, so we suggest overriding the version:

```bash
rustup install 1.90
rustup override set 1.90
```

```bash
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
package_root=$(pwd)
package_name="suricata"
dest_dir=dist

source env.rc

./scripts/bundle.sh
./autogen.sh
CFLAGS="-O3" ./configure --prefix $(pwd)/$dest_dir --enable-dpdk
make -j 16
make install
make install-conf

cd $package_root
```

## Useage

### Configuration

PAMO only extends suricata config file. A sample with PAMO variables is given in `pamo.conf.yaml`.

The minimal think to change is HOME_NET according to the trace you use. But in practice one should read all of them carefully.


### Enable RegEx engine

Taken from https://docs.nvidia.com/doca/archive/doca-v2.2.0/regex-programming-guide/index.html

```bash
host> sudo /etc/init.d/openibd stop
host> sudo echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

On the BF
```bash
echo 1 > /sys/bus/pci/devices/0000\:03\:00.0/regex/pf/regex_en
```

Then re-enable OpenIBD:

```bash
sudo /etc/init.d/openibd start
```

### Running

```bash
log_dir=logs
mkdir -p $log_dir
RULES_PATH=RULES_FILES
dist/bin/suricata -c pamo.conf.yaml --dpdk -l $log_dir  -S ${RULES_PATH} -v
```

### Testing with a trace

Here we take a trace from the Stratosphere dataset as the one we use in the paper is not available:

```bash
wget https://mcfp.felk.cvut.cz/publicDatasets/CTU-Mixed-Capture-1/2015-07-28_mixed.before.infection.pcap
```



### Performance test
A small npf script is given to replay that trace once as fast as possible. NPF will download fastclick and use a script to preload the trace in memory and play the packets out in one step. Now the trace has 500k packets of a unique visitor. This is quite unrealistic as the trace will be accelerated by multiple orders of magnitude and will not effectively have many concurrent connection. But this enables a simpler test setup.


```bash
npf --test play.npf --tags replay dump --cluster client=elrond,nic=0 --variables trace=path/to/2015-07-28_mixed.before.infection.pcap LIMIT=1000000 --show-files --tags gen_pipeline trace_is_ip gen_norx gen_nolat
```
This is just a way to replay the trace quickly, your preferred usual way (pktgen-dpdk, etc) is fine.

After the trace is replayed, you can kill PAMO with CTRL+C:

```bash
Notice: device: 51:00.0: packets: 541045, drops: 135429 (25.03%), invalid chksum: 0 [LiveDeviceListClean:util-device.c:325]
```
Now change the pamo.conf.yaml file to disable the RXP. Set `mpm-algo: ` to `hs`.

Re-do the test and observe the drop has increased by 10%
```bash
Notice: device: 51:00.0: packets: 541045, drops: 187518 (34.66%), invalid chksum: 0 [LiveDeviceListClean:util-device.c:325]
```



## RXPBench
RXPBench, the benchmarking tool for the RXP engine is available at [https:#github.com/UCLouvain-ENSG/PAMO-RXPBench/](https:#github.com/UCLouvain-ENSG/PAMO-RXPBench/).

## Trace acceleration
Scripts to split and rewrite a trace as done in the paper are available at [https:#github.com/uclouvain-ensg/pamo-traces](https:#github.com/uclouvain-ensg/pamo-traces).
