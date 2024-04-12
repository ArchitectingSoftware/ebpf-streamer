## Rebuilding eBPF enabled kernel on Pi

#### Step 1 - Setup a Debian VM on your Mac
Rebuilding the kernel on the Pi takes a very long time.  The best way to do it is to do a cross-compile build on your mac. I used the latest AMD debian.io install image from here:  https://www.debian.org/distrib/

Note that I gave the VM a lot of disk space, memory and CPU.  Specifically 40Gb of disk space, 12G of memory and 4 CPUs.  The more power you provide the VM the quicker the kernel build.

After you have your VM running, login to your VM, the remainder of the instructions are relitive to a terminal on the VM itself. 

#### Step 2 - Install Dependencies
To build the kernel in a cross-compile mode you will need a number of dependencies, from your new VM created in the previous step, run:

```
apt-get install -y git bc bison flex libssl-dev make libc6-dev build-essential libncurses5-dev crossbuild-essential-armhf crossbuild-essential-arm64 libelf-dev dwarves zip
```

#### Step 3 - Obtain a kernel build script
Obtain the zip file from the first post here: https://forums.raspberrypi.com/viewtopic.php?t=343387#

From there unzip the `build-kernel.zip` file, you should see 2 scripts inside of it `build-kernel` and `install-kernel`.

Place the above files into a subdirectory off of your home directory and then make them executable `chmod +x *`

#### Step 4 - Build the Kernel
Run the `build-kernel` script in interactive mode:

```
sudo ./build-kernel -i
```

You will be prompted for a number of things, the following is what I used:

```
cross-compile: yes
config: 4
branch: rpi-6.6.y
suffix: none
old boot mount: no
jobs: 6
menuconfig: y
purge source: n
```
Note you can adjust the parameters as needed.  The jobs can be adjusted to build faster using more CPU threads if needed.  Since the `menuconfig` option was set, once building starts (it will take about a minute becuase of the kernel source download), you will be prompted with an ASCII based UI to adjust kernel build parameters.

See the screen shots from here:  https://medium.com/@oayirnil/three-ways-to-experiment-ebpf-on-raspberry-pi-bcc-python-libbpf-rs-rust-aya-rust-c9edfb373eda

You will navigate to the `Kernel Hacking` section first, then `Compile-time checks and compiler options next`.  From there go to `Debug information`  and set `Rely on the toolchain's implicit default DWARF version`.  Then hit exit.  You can now set the `Generate BTF type info` to yes.  After that, hit `save` and then hit escape multiple times until you get back to a terminal.  Once you get back to the terminal, wait 30 seconds and then type `exit`.  This should start the build.

Note on my machine it took about 15 minutes.

#### Step 5 - Deploy the Kernel
After the build finishes, if all went well, you will have a zip file on the root of your home directly.  In my case the name of the zip file was `kernel-6.6.26-v8.zip`.

You will now `scp` both the kernel zip file, and the `install-kernel` script from Step 3 to your pi.

#### Step 6 - Install the Kernel
Once the 2 files from Step 5 are on your Pi, ssh into your pi.  Then execute:

```
sudo ./install-kernel ./kernel-6.6.26-v8.zip
```
Of course, if your zip file is named differently change it as needed.

You will be prompted if you want to install, hit yes.  This may take some time to uncpompress and generate the final kernel images on your pi.

After everything is installed hit yes to reboot.

#### Step 7 - Verify 
After your pi reboots, ssh into the pi.  If everything went to plan you should have a `/sys/kernel/btf/` directory.
