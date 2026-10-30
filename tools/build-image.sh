#!/usr/bin/env bash
#
# tools/build-image.sh - Build a bootable disk image for Helios
#
# Usage: tools/build-image.sh [kernel-elf] [init-elf] [ps-elf] [output-img]
#
# Defaults:
#   kernel-elf = target/x86_64-unknown-none/debug/kernel-boot
#   init-elf   = target/x86_64-unknown-none/release/init
#   ps-elf     = target/x86_64-unknown-none/release/ps
#   output-img = build/helios.img
#
# The image layout:
#   Sector 0:     MBR (minimal - just jumps to kernel)
#   Sector 1+:    Kernel ELF (loaded by QEMU -kernel, not MBR boot)
#   After kernel: Init ELF + PS ELF (appended as initrd)
#
# Note: QEMU -kernel loads the ELF directly. The initrd contains init + PS
# which the kernel's init process will load and spawn.
#

set -euo pipefail

KERNEL_ELF="${1:-target/x86_64-unknown-none/debug/kernel-boot}"
INIT_ELF="${2:-target/x86_64-unknown-none/release/init}"
PS_ELF="${3:-target/x86_64-unknown-none/release/ps}"
OUTPUT_IMG="${4:-build/helios.img}"

mkdir -p "$(dirname "$OUTPUT_IMG")"

# Verify inputs exist
for f in "$KERNEL_ELF" "$INIT_ELF" "$PS_ELF"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: $f not found" >&2
        exit 1
    fi
done

# Create an initrd containing init + PS
INITRD="build/initrd.img"
mkdir -p build
cp "$INIT_ELF" build/init
cp "$PS_ELF" build/ps

# Create a simple initrd (cPIO format would be ideal, but for now just concatenate)
# The kernel's init process will need to parse this. For now, just concatenate.
cat "$INIT_ELF" "$PS_ELF" > "$INITRD"

# Create a raw disk image
# QEMU can boot directly with -kernel, so we don't strictly need a disk image.
# But having one is useful for future bootloader support.
dd if=/dev/zero of="$OUTPUT_IMG" bs=1M count=1 2>/dev/null

echo "Built:"
echo "  Kernel ELF: $KERNEL_ELF"
echo "  Initrd:     $INITRD"
echo "  Disk image: $OUTPUT_IMG"
echo ""
echo "To boot in QEMU:"
echo "  qemu-system-x86_64 -machine accel=hvf -cpu max -m 256M \\"
echo "    -kernel $KERNEL_ELF -initrd $INITRD -serial stdio -display none -no-reboot -nographic"
