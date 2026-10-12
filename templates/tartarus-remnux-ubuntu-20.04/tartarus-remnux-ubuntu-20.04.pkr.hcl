packer {
  required_plugins {
    proxmox = { version = "= 1.2.3", source = "github.com/badsectorlabs/proxmox" }
  }
}
variable "description" {
  type    = string
  default = "Tartarus-owned Ubuntu 20.04 AMD64 base for REMnux."
}
variable "vm_name" {
  type    = string
  default = "tartarus-remnux-ubuntu-20.04-template"
}
variable "iso_url" {
  type    = string
  default = ""
}
variable "iso_checksum" {
  type    = string
  default = "sha256:f11bda2f2caed8f420802b59f382c25160b114ccc665dbac9c5046e7fceaced2"
}
variable "proxmox_url" { type = string }
variable "proxmox_host" { type = string }
variable "proxmox_username" { type = string }
variable "proxmox_password" {
  type      = string
  sensitive = true
}
variable "proxmox_storage_pool" { type = string }
variable "proxmox_storage_format" { type = string }
variable "proxmox_skip_tls_verify" { type = bool }
variable "proxmox_pool" { type = string }
variable "iso_storage_pool" { type = string }
variable "ansible_home" { type = string }
variable "ludus_nat_interface" { type = string }

source "proxmox-iso" "tartarus_remnux" {
  proxmox_url              = var.proxmox_url
  node                     = var.proxmox_host
  username                 = var.proxmox_username
  password                 = var.proxmox_password
  insecure_skip_tls_verify = var.proxmox_skip_tls_verify
  pool                     = var.proxmox_pool
  vm_name                  = var.vm_name
  template_description     = "Tartarus Ubuntu 20.04 REMnux base; localuser password must be rotated"
  os                       = "l26"
  cores                    = 2
  memory                   = 4096
  scsi_controller          = "virtio-scsi-single"
  disks {
    disk_size    = "128G"
    format       = var.proxmox_storage_format
    storage_pool = var.proxmox_storage_pool
    type         = "virtio"
    discard      = true
    io_thread    = true
  }
  network_adapters {
    bridge = var.ludus_nat_interface
    model  = "virtio"
  }
  iso_url                = var.iso_url != "" ? var.iso_url : "https://cdimage.ubuntu.com/ubuntu-legacy-server/releases/20.04/release/ubuntu-20.04.1-legacy-server-amd64.iso"
  iso_checksum           = var.iso_checksum
  iso_storage_pool       = var.iso_storage_pool
  unmount_iso            = true
  http_directory         = "http"
  boot_key_interval      = "20ms"
  boot_keygroup_interval = "20ms"
  boot_command = [
    "<esc><wait>",
    "<esc><wait>",
    "<enter><wait>",
    "/install/vmlinuz <wait>",
    "auto <wait>",
    "console-setup/ask_detect=false ",
    "debconf/frontend=noninteractive ",
    "debian-installer=en_US ",
    "fb=false ",
    "hostname=remnux ",
    "initrd=/install/initrd.gz ",
    "kbd-chooser/method=us ",
    "keyboard-configuration/modelcode=SKIP ",
    "keyboard-configuration/layout=USA ",
    "keyboard-configuration/variant=USA ",
    "locale=en_US ",
    "passwd/username=localuser ",
    "passwd/user-fullname=localuser ",
    "passwd/user-password=password ",
    "passwd/user-password-again=password ",
    "noapic ",
    "preseed/url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg ",
    " -- <enter>",
  ]
  communicator     = "ssh"
  ssh_username     = "localuser"
  ssh_password     = "password"
  ssh_wait_timeout = "35m"
}

build {
  sources = ["source.proxmox-iso.tartarus_remnux"]
  provisioner "shell" {
    execute_command = "echo 'password' | sudo -S sh -c '{{ .Vars }} {{ .Path }}'"
    inline = [
      "apt-get update",
      "DEBIAN_FRONTEND=noninteractive apt-get install -y python3 qemu-guest-agent sudo auditd audispd-plugins jq rsync curl dumpcap inetsim gdb radare2 lsof openssl unzip iproute2 iputils-ping netcat-openbsd build-essential texinfo libgmp-dev libmpfr-dev python3-dev cmake flex bison libpcap-dev libssl-dev swig zlib1g-dev libmaxminddb-dev",
      "apt-get clean"
    ]
  }
  provisioner "ansible" {
    playbook_file      = "ansible/remnux.yml"
    use_proxy          = false
    user               = "localuser"
    extra_arguments    = ["--extra-vars", "{ansible_password: password, ansible_sudo_pass: password}"]
    ansible_env_vars   = ["ANSIBLE_HOME=${var.ansible_home}"]
    skip_version_check = true
  }
  provisioner "shell" {
    execute_command = "echo 'password' | sudo -S sh -c '{{ .Vars }} {{ .Path }}'"
    inline = [
      "passwd -l root",
      "truncate -s 0 /etc/machine-id",
      "rm -f /etc/ssh/ssh_host_*"
    ]
  }
}
