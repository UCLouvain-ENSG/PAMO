# PAMO
The repository containing PAMO source code based on Suricata. PAMO adds support for the RXP engine through DPDK. In practice tested with a BlueField 2, but also available in the BlueField 3 and some Marvell NICs. PAMO with the RXP engine disabled is effectively plain old Suricata.

We first explain how to install the dependencies (DPDK, DOCA) and compile PAMO.
We then explain how to run PAMO.
We present two test cases: a first one showing the number of match/alerts is the same with and without the RXP engine.
A second test case comparing the performance of PAMO with and without the RXP engine.

## Installation
Here are the steps to compile the dependencies, followed by PAMO itself.

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

## Usage

### Configuration

PAMO only extends suricata config file. A sample with PAMO variables is given in `pamo.conf.yaml`.

The minimal think to change is HOME_NET according to the trace you use. But in practice one should read all parameters carefully.

Here is a view of the main options for PAMO:
```yaml
  - interface: 51:00.0 # PCIe address of the NIC port
      threads: 4 #Not PAMO specufic but important : how much threads used
      rxp-min-buflen: -16 # minimum number of bytes that buffer needs to contain to be evaluated by RXP engine. Smaller buffers are passed to HS. Negative values invoke the automatic scaling that, when under contention, the RXP will only process bigger buffers.
      rxp-desc: 256 #Number of descriptor per RXP queues. There is one per threads.
      rxp-desc-max: 2048 #Max number of total descriptors. So if there is more than 8 queues with this values, then rxp-desc will be 128.

      rsspp-enable: no
      rxp-buffer-max: 0

      # This is a list of MPM group IDs which will be compiled to RXP, groups not listed here will be compiled to SW MPM (Hyperscan)
      rxp-mpm-groupids: [ all ] # default is all. This did not bring much improvement so we kept it out of the paper and just offload all groups
      interrupt-mode: no # true switch to interrupt mode. Breaks PAMO. If you're worried about energy useage of polling, use Sloth

```

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

Then re-enable OpenIBD on the host:

```bash
sudo /etc/init.d/openibd start
```

### Running

The general command to run PAMO is the following. We propose below two small experiments, one about functionality, and one on performance.
```bash
log_dir=logs
mkdir -p $log_dir
RULES_PATH=RULES_FILES
dist/bin/suricata -c pamo.conf.yaml --dpdk -l $log_dir  -S ${RULES_PATH} -v
```

## Functional experiments with a trace

We now propose two tests. First we use a public trace and rules set to verify that we have the same amount of matches with and without RXP. We then do a test to compare the performance with and without the RXP.


### Traces
We take two traces from the Stratosphere dataset as the one we use in the paper cannot be shared. The first trace is infected, used for the functional test. The second one is the full mix.

```bash
wget https://mcfp.felk.cvut.cz/publicDatasets/CTU-Mixed-Capture-1/2015-07-28_mixed.pcap
wget https://mcfp.felk.cvut.cz/publicDatasets/CTU-Mixed-Capture-1/2015-07-28_mixed.before.infection.pcap
```

The rules set is already in this repository. It's the ET rules set without the 49 rules that match only a single byte.

### Testbed

We have two machines, one with a BlueField 2 DPU, and one which acts a the generator. The generator has a ConnectX 6. They're connected back to back.

### Functional test

Run Suricata with:
```bash
sudo -E LD_LIBRARY_PATH=$LD_LIBRARY_PATH SC_LOG_LEVEL=info dist/bin/suricata -c $(pwd)/pamo.conf.yaml --dpdk -l logs -S ./emerging-all-rxp-modified.rules --set mpm-algo=rxp
```
The first time you load the ruleset, the rules will be compiled. It might take a lot of time (1hour). Next times PAMO will use a cache in /tmp instead, so you only rebuild once.

On the other server, replay the trace at small speed, like 1Gbps so there is no packet drop:
```
sudo tcpreplay -M 1000 -i enp152s0f0np0 2015-07-28_mixed.pcap
```

Now kill PAMO with CTRL+C and observe the number of alerts:
```
Info: counters: Alerts: 387 [StatsLogSummary:counters.c:890]
Notice: device: 51:00.0: packets: 1437983, drops: 0 (0.00%), invalid chksum: 0 [LiveDeviceListClean:util-device.c:325]
Notice: dpdk: 51:00.0: releasing packet mempool [DPDKFreeDevice:util-dpdk.c:165]
```

The number of alerts should be around 387, there is a bit of variability due to how Suricata randomizes reassambly to avoid eviction.

Now to compare with HS (base Suricata), change `--set mpm-algo rxp` by `--set mpm-algo hs`
```
Info: counters: Alerts: 388 [StatsLogSummary:counters.c:890]
Notice: device: 51:00.0: packets: 1437982, drops: 0 (0.00%), invalid chksum: 0 [LiveDeviceListClean:util-device.c:325]
Notice: dpdk: 51:00.0: releasing packet mempool [DPDKFreeDevice:util-dpdk.c:165]
```


### Performance test

`tcpreplay` is not able to replay at very high speeds. On our system, at full rate (-t) tcpreplay does not saturate aven a single core of suricata. We therefore use the toolchain used in the paper, but in a different mode.

A small [NPF](https://github.com/tbarbette/npf/) script is given to replay the trace once as fast as possible. NPF will download fastclick and use a script to preload the trace in memory and play the packets out in one step. Now the trace has 500k packets of a unique visitor. This is quite unrealistic as the trace will be accelerated by multiple orders of magnitude and will not effectively have many concurrent connection, as discussed in the paper. In the paper we also use a zero-loss throughput, iteratively augmenting the number of parallel windows. But this enables a simpler test setup.


```bash
pip install --user npf
npf --test play.npf --tags replay dump --cluster client=elrond,nic=0 --variables trace=path/to/2015-07-28_mixed.before.infection.pcap LIMIT=1000000 --show-files --tags gen_pipeline trace_is_ip gen_norx gen_nolat
```
This is just a way to replay the trace quickly, your preferred usual way (pktgen-dpdk, etc) is fine.

After the trace is replayed, you can kill PAMO with CTRL+C:

```bash
Info: counters: Alerts: 46 [StatsLogSummary:counters.c:890]
Notice: device: 51:00.0: packets: 541045, drops: 254274 (47.00%), invalid chksum: 0 [LiveDeviceListClean:util-device.c:325]
Notice: dpdk: 51:00.0: releasing packet mempool [DPDKFreeDevice:util-dpdk.c:165]
```
Note that PAMO dropped 47% of traffic.

As before, change the Suricata launch line to use HS, and launch the test again:

```bash
Info: counters: Alerts: 6 [StatsLogSummary:counters.c:890]
Notice: device: 51:00.0: packets: 541044, drops: 334480 (61.82%), invalid chksum: 0 [LiveDeviceListClean:util-device.c:325]
Notice: dpdk: 51:00.0: releasing packet mempool [DPDKFreeDevice:util-dpdk.c:165]
```
Without the RXP, the drop rate increases to 61.82%. PAMO can process around 30% more traffic (NB: again, for a correct measurement we need to do zero-loss throughput as in the paper).

## RXPBench
RXPBench, the benchmarking tool for the RXP engine is available at [https:#github.com/UCLouvain-ENSG/PAMO-RXPBench/](https:#github.com/UCLouvain-ENSG/PAMO-RXPBench/).

## Trace acceleration
Scripts to split and rewrite a trace as done in the paper are available at [https:#github.com/uclouvain-ensg/pamo-traces](https:#github.com/uclouvain-ensg/pamo-traces).
