packer {
  required_plugins {
    qemu = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

source "qemu" "zentryc" {
  vm_name          = "zentryc-${var.version}"
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  output_directory = "${var.output_dir}/qemu"

  disk_size    = var.disk_size
  disk_image   = false
  format       = "qcow2"
  accelerator  = "kvm"

  memory   = var.memory
  cpus     = var.cpus
  headless = var.headless

  http_directory = "http"

  ssh_username = "packer"
  ssh_password = "packer"
  ssh_timeout  = "30m"

  boot_wait = "5s"
  boot_command = [
    "c<wait>",
    "linux /casper/vmlinuz --- autoinstall ds='nocloud-net;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/' ",
    "<enter><wait>",
    "initrd /casper/initrd<enter><wait>",
    "boot<enter>"
  ]

  shutdown_command = "echo 'packer' | sudo -S shutdown -P now"
  shutdown_timeout = "5m"

  qemuargs = [
    ["-cpu", "host"],
    ["-smp", "${var.cpus}"],
  ]
}

build {
  sources = ["source.qemu.zentryc"]

  # Upload the compiled tarball
  provisioner "file" {
    source      = var.compiled_tarball
    destination = "/tmp/zentryc-compiled.tar.gz"
  }

  # Upload branding files
  provisioner "file" {
    source      = "files/"
    destination = "/tmp/packer-files"
  }

  # Run provisioner scripts in order
  provisioner "shell" {
    execute_command = "echo 'packer' | sudo -S bash -euo pipefail '{{ .Path }}'"
    scripts = [
      "scripts/01-base-setup.sh",
      "scripts/02-install-zentryc.sh",
      "scripts/03-configure-cli.sh",
      "scripts/04-harden.sh",
      "scripts/05-cleanup.sh",
    ]
  }

  # Copy QCOW2 to output (it's already in qcow2 format from QEMU)
  post-processor "shell-local" {
    inline = [
      "mkdir -p ${var.output_dir}/release",
      "cp ${var.output_dir}/qemu/zentryc-${var.version} ${var.output_dir}/release/zentryc-${var.version}.qcow2",
      "echo 'QCOW2 image: ${var.output_dir}/release/zentryc-${var.version}.qcow2'",
    ]
  }

  # Create OVA from QCOW2
  post-processor "shell-local" {
    inline = [
      "bash scripts/create-ova.sh ${var.output_dir}/release/zentryc-${var.version}.qcow2 ${var.version} ${var.output_dir}/release",
      "echo 'OVA image: ${var.output_dir}/release/zentryc-${var.version}.ova'",
    ]
  }
}
