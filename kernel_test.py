#!/usr/bin/env python3

import argparse
import os
import subprocess
import tempfile


INITRD_CFG = '''
# This is a very simple, default initramfs

dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
nod /dev/tty0 0640 0 0 c 4 0
nod /dev/tty1 0640 0 0 c 4 1
nod /dev/tty2 0640 0 0 c 4 2
nod /dev/tty3 0640 0 0 c 4 3
nod /dev/tty4 0640 0 0 c 4 4
nod /dev/tty5 0640 0 0 c 4 5
dir /root 0700 0 0
#
nod /dev/loop0 644 0 0 b 7 0
dir /proc 755 0 0
dir /sys 755 0 0
dir /mnt 755 0 0
dir /tmp 777 0 0
# file /kinit usr/kinit/kinit 0755 0 0
# slink /init kinit 0755 0 0

#####################
# /home/tehnerd/projects/linux/initramfs_root/
# Last modified: 1500573913.7706258850

# modules to test
dir /modules 755 0 0
# file /modules/e1000.ko /tmp/linux/initramfs_root/modules/e1000.ko 755 0 0
#

dir /bin 755 0 0
slink /bin/acpid busybox 777 0 0
slink /bin/addgroup busybox 777 0 0
slink /bin/add-shell busybox 777 0 0
slink /bin/adduser busybox 777 0 0
slink /bin/adjtimex busybox 777 0 0
slink /bin/ar busybox 777 0 0
slink /bin/arp busybox 777 0 0
slink /bin/arping busybox 777 0 0
slink /bin/ash busybox 777 0 0
slink /bin/awk busybox 777 0 0
slink /bin/base64 busybox 777 0 0
slink /bin/basename busybox 777 0 0
slink /bin/bbconfig busybox 777 0 0
slink /bin/beep busybox 777 0 0
slink /bin/blkid busybox 777 0 0
slink /bin/blockdev busybox 777 0 0
slink /bin/bootchartd busybox 777 0 0
slink /bin/brctl busybox 777 0 0
slink /bin/bunzip2 busybox 777 0 0
file /bin/busybox {busybox_loc} 755 0 0
slink /bin/bzcat busybox 777 0 0
slink /bin/bzip2 busybox 777 0 0
slink /bin/cal busybox 777 0 0
slink /bin/cat busybox 777 0 0
slink /bin/catv busybox 777 0 0
slink /bin/chat busybox 777 0 0
slink /bin/chattr busybox 777 0 0
slink /bin/chgrp busybox 777 0 0
slink /bin/chmod busybox 777 0 0
slink /bin/chown busybox 777 0 0
slink /bin/chpasswd busybox 777 0 0
slink /bin/chpst busybox 777 0 0
slink /bin/chroot busybox 777 0 0
slink /bin/chrt busybox 777 0 0
slink /bin/chvt busybox 777 0 0
slink /bin/cksum busybox 777 0 0
slink /bin/clear busybox 777 0 0
slink /bin/cmp busybox 777 0 0
slink /bin/comm busybox 777 0 0
slink /bin/conspy busybox 777 0 0
slink /bin/cp busybox 777 0 0
slink /bin/cpio busybox 777 0 0
slink /bin/crond busybox 777 0 0
slink /bin/crontab busybox 777 0 0
slink /bin/cryptpw busybox 777 0 0
slink /bin/cttyhack busybox 777 0 0
slink /bin/cut busybox 777 0 0
slink /bin/date busybox 777 0 0
slink /bin/dc busybox 777 0 0
slink /bin/dd busybox 777 0 0
slink /bin/deallocvt busybox 777 0 0
slink /bin/delgroup busybox 777 0 0
slink /bin/deluser busybox 777 0 0
slink /bin/depmod busybox 777 0 0
slink /bin/devmem busybox 777 0 0
slink /bin/df busybox 777 0 0
slink /bin/dhcprelay busybox 777 0 0
slink /bin/diff busybox 777 0 0
slink /bin/dirname busybox 777 0 0
slink /bin/dmesg busybox 777 0 0
slink /bin/dnsd busybox 777 0 0
slink /bin/dnsdomainname busybox 777 0 0
slink /bin/dos2unix busybox 777 0 0
slink /bin/du busybox 777 0 0
slink /bin/dumpkmap busybox 777 0 0
slink /bin/dumpleases busybox 777 0 0
slink /bin/echo busybox 777 0 0
slink /bin/ed busybox 777 0 0
slink /bin/egrep busybox 777 0 0
slink /bin/eject busybox 777 0 0
slink /bin/env busybox 777 0 0
slink /bin/envdir busybox 777 0 0
slink /bin/envuidgid busybox 777 0 0
slink /bin/ether-wake busybox 777 0 0
slink /bin/expand busybox 777 0 0
slink /bin/expr busybox 777 0 0
slink /bin/fakeidentd busybox 777 0 0
slink /bin/false busybox 777 0 0
slink /bin/fbset busybox 777 0 0
slink /bin/fbsplash busybox 777 0 0
slink /bin/fdflush busybox 777 0 0
slink /bin/fdformat busybox 777 0 0
slink /bin/fdisk busybox 777 0 0
slink /bin/fgconsole busybox 777 0 0
slink /bin/fgrep busybox 777 0 0
slink /bin/find busybox 777 0 0
slink /bin/findfs busybox 777 0 0
slink /bin/flock busybox 777 0 0
slink /bin/fold busybox 777 0 0
slink /bin/free busybox 777 0 0
slink /bin/freeramdisk busybox 777 0 0
slink /bin/fsck busybox 777 0 0
slink /bin/fsck.minix busybox 777 0 0
slink /bin/fstrim busybox 777 0 0
slink /bin/fsync busybox 777 0 0
slink /bin/ftpd busybox 777 0 0
slink /bin/ftpget busybox 777 0 0
slink /bin/ftpput busybox 777 0 0
slink /bin/fuser busybox 777 0 0
slink /bin/getopt busybox 777 0 0
slink /bin/getty busybox 777 0 0
slink /bin/grep busybox 777 0 0
slink /bin/groups busybox 777 0 0
slink /bin/gunzip busybox 777 0 0
slink /bin/gzip busybox 777 0 0
slink /bin/halt busybox 777 0 0
slink /bin/hd busybox 777 0 0
slink /bin/hdparm busybox 777 0 0
slink /bin/head busybox 777 0 0
slink /bin/hexdump busybox 777 0 0
slink /bin/hostid busybox 777 0 0
slink /bin/hostname busybox 777 0 0
slink /bin/httpd busybox 777 0 0
slink /bin/hush busybox 777 0 0
slink /bin/hwclock busybox 777 0 0
slink /bin/id busybox 777 0 0
slink /bin/ifconfig busybox 777 0 0
slink /bin/ifdown busybox 777 0 0
slink /bin/ifenslave busybox 777 0 0
slink /bin/ifplugd busybox 777 0 0
slink /bin/ifup busybox 777 0 0
slink /bin/inetd busybox 777 0 0
slink /bin/init busybox 777 0 0
slink /bin/insmod busybox 777 0 0
slink /bin/install busybox 777 0 0
slink /bin/ionice busybox 777 0 0
slink /bin/iostat busybox 777 0 0
slink /bin/ip busybox 777 0 0
slink /bin/ipaddr busybox 777 0 0
slink /bin/ipcalc busybox 777 0 0
slink /bin/ipcrm busybox 777 0 0
slink /bin/ipcs busybox 777 0 0
slink /bin/iplink busybox 777 0 0
slink /bin/iproute busybox 777 0 0
slink /bin/iprule busybox 777 0 0
slink /bin/iptunnel busybox 777 0 0
slink /bin/kbd_mode busybox 777 0 0
slink /bin/kill busybox 777 0 0
slink /bin/killall5 busybox 777 0 0
slink /bin/killall busybox 777 0 0
slink /bin/klogd busybox 777 0 0
slink /bin/last busybox 777 0 0
slink /bin/less busybox 777 0 0
slink /bin/linux32 busybox 777 0 0
slink /bin/linux64 busybox 777 0 0
slink /bin/linuxrc busybox 777 0 0
slink /bin/ln busybox 777 0 0
slink /bin/loadfont busybox 777 0 0
slink /bin/loadkmap busybox 777 0 0
slink /bin/logger busybox 777 0 0
slink /bin/login busybox 777 0 0
slink /bin/logname busybox 777 0 0
slink /bin/logread busybox 777 0 0
slink /bin/losetup busybox 777 0 0
slink /bin/lpd busybox 777 0 0
slink /bin/lpq busybox 777 0 0
slink /bin/lpr busybox 777 0 0
slink /bin/ls busybox 777 0 0
slink /bin/lsattr busybox 777 0 0
slink /bin/lsmod busybox 777 0 0
slink /bin/lsof busybox 777 0 0
slink /bin/lspci busybox 777 0 0
slink /bin/lsusb busybox 777 0 0
slink /bin/lzcat busybox 777 0 0
slink /bin/lzma busybox 777 0 0
slink /bin/lzop busybox 777 0 0
slink /bin/lzopcat busybox 777 0 0
slink /bin/makedevs busybox 777 0 0
slink /bin/makemime busybox 777 0 0
slink /bin/man busybox 777 0 0
slink /bin/md5sum busybox 777 0 0
slink /bin/mdev busybox 777 0 0
slink /bin/mesg busybox 777 0 0
slink /bin/microcom busybox 777 0 0
slink /bin/mkdir busybox 777 0 0
slink /bin/mkdosfs busybox 777 0 0
slink /bin/mke2fs busybox 777 0 0
slink /bin/mkfifo busybox 777 0 0
slink /bin/mkfs.ext2 busybox 777 0 0
slink /bin/mkfs.minix busybox 777 0 0
slink /bin/mkfs.vfat busybox 777 0 0
slink /bin/mknod busybox 777 0 0
slink /bin/mkpasswd busybox 777 0 0
slink /bin/mkswap busybox 777 0 0
slink /bin/mktemp busybox 777 0 0
slink /bin/modinfo busybox 777 0 0
slink /bin/modprobe busybox 777 0 0
slink /bin/more busybox 777 0 0
slink /bin/mount busybox 777 0 0
slink /bin/mountpoint busybox 777 0 0
slink /bin/mpstat busybox 777 0 0
slink /bin/msh busybox 777 0 0
slink /bin/mt busybox 777 0 0
slink /bin/mv busybox 777 0 0
slink /bin/nameif busybox 777 0 0
slink /bin/nanddump busybox 777 0 0
slink /bin/nandwrite busybox 777 0 0
slink /bin/nbd-client busybox 777 0 0
slink /bin/nc busybox 777 0 0
slink /bin/netstat busybox 777 0 0
slink /bin/nice busybox 777 0 0
slink /bin/nmeter busybox 777 0 0
slink /bin/nohup busybox 777 0 0
slink /bin/nslookup busybox 777 0 0
slink /bin/ntpd busybox 777 0 0
slink /bin/od busybox 777 0 0
slink /bin/openvt busybox 777 0 0
slink /bin/passwd busybox 777 0 0
slink /bin/patch busybox 777 0 0
slink /bin/pgrep busybox 777 0 0
slink /bin/pidof busybox 777 0 0
slink /bin/ping6 busybox 777 0 0
slink /bin/ping busybox 777 0 0
slink /bin/pipe_progress busybox 777 0 0
slink /bin/pivot_root busybox 777 0 0
slink /bin/pkill busybox 777 0 0
slink /bin/pmap busybox 777 0 0
slink /bin/popmaildir busybox 777 0 0
slink /bin/poweroff busybox 777 0 0
slink /bin/powertop busybox 777 0 0
slink /bin/printenv busybox 777 0 0
slink /bin/printf busybox 777 0 0
slink /bin/ps busybox 777 0 0
slink /bin/pscan busybox 777 0 0
slink /bin/pstree busybox 777 0 0
slink /bin/pwd busybox 777 0 0
slink /bin/pwdx busybox 777 0 0
slink /bin/raidautorun busybox 777 0 0
slink /bin/rdate busybox 777 0 0
slink /bin/rdev busybox 777 0 0
slink /bin/readahead busybox 777 0 0
slink /bin/readlink busybox 777 0 0
slink /bin/readprofile busybox 777 0 0
slink /bin/realpath busybox 777 0 0
slink /bin/reboot busybox 777 0 0
slink /bin/reformime busybox 777 0 0
slink /bin/remove-shell busybox 777 0 0
slink /bin/renice busybox 777 0 0
slink /bin/reset busybox 777 0 0
slink /bin/resize busybox 777 0 0
slink /bin/rev busybox 777 0 0
slink /bin/rm busybox 777 0 0
slink /bin/rmdir busybox 777 0 0
slink /bin/rmmod busybox 777 0 0
slink /bin/route busybox 777 0 0
slink /bin/rpm2cpio busybox 777 0 0
slink /bin/rpm busybox 777 0 0
slink /bin/rtcwake busybox 777 0 0
slink /bin/runlevel busybox 777 0 0
slink /bin/run-parts busybox 777 0 0
slink /bin/runsv busybox 777 0 0
slink /bin/runsvdir busybox 777 0 0
slink /bin/rx busybox 777 0 0
slink /bin/script busybox 777 0 0
slink /bin/scriptreplay busybox 777 0 0
slink /bin/sed busybox 777 0 0
slink /bin/sendmail busybox 777 0 0
slink /bin/seq busybox 777 0 0
slink /bin/setarch busybox 777 0 0
slink /bin/setconsole busybox 777 0 0
slink /bin/setfont busybox 777 0 0
slink /bin/setkeycodes busybox 777 0 0
slink /bin/setlogcons busybox 777 0 0
slink /bin/setserial busybox 777 0 0
slink /bin/setsid busybox 777 0 0
slink /bin/setuidgid busybox 777 0 0
slink /bin/sh busybox 777 0 0
slink /bin/sha1sum busybox 777 0 0
slink /bin/sha256sum busybox 777 0 0
slink /bin/sha3sum busybox 777 0 0
slink /bin/sha512sum busybox 777 0 0
slink /bin/showkey busybox 777 0 0
slink /bin/slattach busybox 777 0 0
slink /bin/sleep busybox 777 0 0
slink /bin/smemcap busybox 777 0 0
slink /bin/softlimit busybox 777 0 0
slink /bin/sort busybox 777 0 0
slink /bin/split busybox 777 0 0
slink /bin/start-stop-daemon busybox 777 0 0
slink /bin/stat busybox 777 0 0
slink /bin/strings busybox 777 0 0
slink /bin/stty busybox 777 0 0
slink /bin/su busybox 777 0 0
slink /bin/sulogin busybox 777 0 0
slink /bin/sum busybox 777 0 0
slink /bin/sv busybox 777 0 0
slink /bin/svlogd busybox 777 0 0
slink /bin/swapoff busybox 777 0 0
slink /bin/swapon busybox 777 0 0
slink /bin/switch_root busybox 777 0 0
slink /bin/sync busybox 777 0 0
slink /bin/sysctl busybox 777 0 0
slink /bin/syslogd busybox 777 0 0
slink /bin/tac busybox 777 0 0
slink /bin/tail busybox 777 0 0
slink /bin/tar busybox 777 0 0
slink /bin/tcpsvd busybox 777 0 0
slink /bin/tee busybox 777 0 0
slink /bin/telnet busybox 777 0 0
slink /bin/telnetd busybox 777 0 0
slink /bin/test busybox 777 0 0
slink /bin/tftp busybox 777 0 0
slink /bin/tftpd busybox 777 0 0
slink /bin/time busybox 777 0 0
slink /bin/timeout busybox 777 0 0
slink /bin/top busybox 777 0 0
slink /bin/touch busybox 777 0 0
slink /bin/tr busybox 777 0 0
slink /bin/traceroute6 busybox 777 0 0
slink /bin/traceroute busybox 777 0 0
slink /bin/true busybox 777 0 0
slink /bin/tty busybox 777 0 0
slink /bin/ttysize busybox 777 0 0
slink /bin/tunctl busybox 777 0 0
slink /bin/ubiattach busybox 777 0 0
slink /bin/ubidetach busybox 777 0 0
slink /bin/ubimkvol busybox 777 0 0
slink /bin/ubirmvol busybox 777 0 0
slink /bin/ubirsvol busybox 777 0 0
slink /bin/ubiupdatevol busybox 777 0 0
slink /bin/udhcpc busybox 777 0 0
slink /bin/udhcpd busybox 777 0 0
slink /bin/udpsvd busybox 777 0 0
slink /bin/umount busybox 777 0 0
slink /bin/uname busybox 777 0 0
slink /bin/uncompress busybox 777 0 0
slink /bin/unexpand busybox 777 0 0
slink /bin/uniq busybox 777 0 0
slink /bin/unix2dos busybox 777 0 0
slink /bin/unlzma busybox 777 0 0
slink /bin/unlzop busybox 777 0 0
slink /bin/unxz busybox 777 0 0
slink /bin/unzip busybox 777 0 0
slink /bin/uptime busybox 777 0 0
slink /bin/users busybox 777 0 0
slink /bin/usleep busybox 777 0 0
slink /bin/uudecode busybox 777 0 0
slink /bin/uuencode busybox 777 0 0
slink /bin/vconfig busybox 777 0 0
slink /bin/vi busybox 777 0 0
slink /bin/vlock busybox 777 0 0
slink /bin/volname busybox 777 0 0
slink /bin/wall busybox 777 0 0
slink /bin/watch busybox 777 0 0
slink /bin/watchdog busybox 777 0 0
slink /bin/wc busybox 777 0 0
slink /bin/wget busybox 777 0 0
slink /bin/which busybox 777 0 0
slink /bin/who busybox 777 0 0
slink /bin/whoami busybox 777 0 0
slink /bin/whois busybox 777 0 0
slink /bin/xargs busybox 777 0 0
slink /bin/xz busybox 777 0 0
slink /bin/xzcat busybox 777 0 0
slink /bin/yes busybox 777 0 0
slink /bin/zcat busybox 777 0 0
slink /bin/zcip busybox 777 0 0

file /init {initrd_root}/init 755 0 0
'''

INIT_FILE = '''#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t configfs none /sys/kernel/config
mount -t debugfs none /sys/kernel/debug
mount -t tmpfs none /tmp
mount -t devtmpfs none /dev

# populate /dev
# mknod -m 622 /dev/console c 5 1
# mknod -m 666 /dev/null c 1 3
# mknod -m 666 /dev/zero c 1 5
# mknod -m 666 /dev/ptmx c 5 2
# mknod -m 666 /dev/tty c 5 0
# mknod -m 444 /dev/random c 1 8
# mknod -m 444 /dev/urandom c 1 9
ln -s /proc/self/fd /dev/fd
ln -s /proc/self/fd/0 /dev/stdin
ln -s /proc/self/fd/1 /dev/stdout
ln -s /proc/self/fd/2 /dev/stderr
ln -s /proc/kcore /dev/core
mkdir /dev/pts
mkdir /dev/shm
mount -t devpts -o gid=4,mode=620 none /dev/pts
mount -t tmpfs none /dev/shm

# Test setup commands here:
# insmod /lib/modules/$(uname -r)/kernel/...
# to attach shared files:
# insmod /modules/9pnet.ko
# insmod /modules/9pnet_virtio.ko
# insmod /modules/virtio_blk.ko
# mount -t 9p -o trans=virtio,version=9p2000.L hostshare1 /tmp/host_files
# to switch: exec switch_root /newroot /sbin/init
{}
'''

INTERACTIVE_BOOT = "exec /bin/sh -i"
FAST_BOOT = '''
for module in $(ls /modules/)
do
    insmod /modules/${module}
done
mkdir /rd/
mount /dev/vda1 /rd/
exec switch_root /rd/ /sbin/init
'''

DEFAULT_MODULES = [
    "e1000",
    "9pnet",
    "9pnet_virtio",
    "*virtio*",
]

QEMU_LINE = '''
{} -smp {} -boot c -m {} -k en-us -nographic -serial mon:stdio \
  -drive file={},if=virtio \
  -kernel {}/arch/x86_64/boot/bzImage -initrd {} \
  -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::10022-:22 \
  -append "root=/dev/sda1 ipv6.autoconf=0 biosdevname=0 net.ifnames=0 fsck.repair=yes pcie_pme=nomsi console=tty0 console=ttyS0,57600 security=selinux selinux=1 enforcing=0" \
  -fsdev local,security_model=passthrough,id=fsdev1,path={} \
  -device virtio-9p-pci,id=fs1,fsdev=fsdev1,mount_tag=hostshare1 \
  {}
'''

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--linux", "-l", default="/home/tehnerd/linux",
            help="Path to linux src")
    parser.add_argument("--initramfs", "-i", default="/tmp/initramfs.cpio",
            help="where to save initramfs")
    parser.add_argument("--modules", action='store_true',
            help="add  modules from kernel dir")
    parser.add_argument("--module_name", default="*",
            help="name of the module to add")
    parser.add_argument("--disk", default="/path/to/disk/image",
            help="path to disk image file")
    parser.add_argument("--vm", action='store_true',
            help="use qemu instead of kvm (e.g. nested vm)")
    parser.add_argument("--small", action='store_true',
            help="use less memory (e.g. runs on vm)")
    parser.add_argument("--local_dir", type=str, default="/home/tehnerd/",
            help="location of 9p mapped directory")
    parser.add_argument("--fast", action='store_true',
            help="fast boot into VM image")
    parser.add_argument("--br", action='store_true',
            help="spawn vm w/ 2nd interface for net tests")
    args = parser.parse_args()
    if args.vm:
        args.small = True
    return args


def run_cmd(cmd):
    tmp_bash_file = tempfile.NamedTemporaryFile()
    with open(tmp_bash_file.name, "w") as fd:
        fd.write(cmd)
    output = subprocess.check_output("bash -x {}".format(tmp_bash_file.name).split())
    return output



def get_module(linux, module_name, modules_dict):
    cmd = f'find {linux} -name "{module_name}.ko" '
    output = run_cmd(cmd)
    for module in output.decode().split("\n"):
        module_name = module.split(linux)
        if len(module_name) < 2:
            continue
        modules_dict[module_name[1]] = module

def create_initramfs_cfg(args):
    initdir = tempfile.TemporaryDirectory()
    busybox = "/usr/sbin/busybox"
    if not os.path.exists(busybox):
        busybox = "/bin/busybox"
        if not os.path.exists(busybox):
            raise Exception(f"Can't find busybox at {busybox}")
    modules_dict = {}
    for module in DEFAULT_MODULES:
        get_module(args.linux, module, modules_dict)
    if args.modules:
        get_module(args.linux, args.module_name, modules_dict)
    with open(os.path.join(initdir.name, "initrd_cfg"), "w") as fd:
        config = INITRD_CFG.format(
                busybox_loc = busybox,
                initrd_root = initdir.name)
        fd.write(config)
        for module in modules_dict:
            cfg_line = "\nfile /modules/{} {} 755 0 0".format(
                    os.path.basename(module),
                    modules_dict[module])
            fd.write(cfg_line)
    with open(os.path.join(initdir.name, "init"), "w") as fd:
        if args.fast:
            init_suffix = FAST_BOOT
        else:
            init_suffix = INTERACTIVE_BOOT
        init = INIT_FILE.format(init_suffix)
        fd.write(init)
    return initdir

def create_initramfs(args, initdir):
    print(os.listdir(initdir.name))
    cmd = "cd {linux_dir} && ./usr/gen_init_cpio {initramfs_cfg_dir}/initrd_cfg  | gzip > {initramfs}"
    cmd = cmd.format(
            linux_dir = args.linux,
            initramfs_cfg_dir = initdir.name,
            initramfs = args.initramfs)
    output = run_cmd(cmd)
    print(f"initramfs created: {output}")



def main():
    args = parse_args()
    if not os.path.exists(args.linux):
        raise Exception("can't find linux src")
    initdir = create_initramfs_cfg(args)
    create_initramfs(args, initdir)
    print("now you can run vm with this line:")
    if args.small:
        mem = 512
        cpu = 1
    else:
        mem = 2048
        cpu = 4
    if args.vm:
        qemu_cmd = "qemu-system-x86_64"
    else:
        qemu_cmd = "qemu-kvm"
    if args.br:
        brcmd = "-device e1000,netdev=net1 -netdev tap,id=net1"
        qemu_cmd = "sudo " + qemu_cmd
    else:
        brcmd = ""
    print(QEMU_LINE.format(
            qemu_cmd, cpu, mem, args.disk, args.linux, args.initramfs,
            args.local_dir, brcmd))




if __name__ == "__main__":
    main()
