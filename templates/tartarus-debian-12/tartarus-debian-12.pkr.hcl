packer {
  required_plugins {
    proxmox = { version = "= 1.2.3", source = "github.com/badsectorlabs/proxmox" }
  }
}
variable "description" {
  type    = string
  default = "Tartarus-owned Debian 12.15 AMD64 analysis base."
}
variable "vm_name" {
  type    = string
  default = "tartarus-debian-12-template"
}
variable "iso_url" {
  type    = string
  default = ""
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

source "proxmox-iso" "tartarus_debian12" {
  proxmox_url              = var.proxmox_url
  node                     = var.proxmox_host
  username                 = var.proxmox_username
  password                 = var.proxmox_password
  insecure_skip_tls_verify = var.proxmox_skip_tls_verify
  pool                     = var.proxmox_pool
  vm_name                  = var.vm_name
  template_description     = "Tartarus Debian 12.15; Debian bootstrap password is locked during deployment"
  os                       = "l26"
  cores                    = 2
  memory                   = 2048
  scsi_controller          = "virtio-scsi-single"
  disks {
    disk_size    = "64G"
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
  iso_url           = var.iso_url != "" ? var.iso_url : "https://cdimage.debian.org/cdimage/archive/12.15.0/amd64/iso-cd/debian-12.15.0-amd64-netinst.iso"
  iso_storage_pool  = var.iso_storage_pool
  unmount_iso       = true
  http_directory    = "http"
  boot_wait         = "15s"
  boot_key_interval = "100ms"
  boot_command = [
    "<down><tab>",
    "<wait>preseed/url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg ",
    "<wait>language=en locale=en_US.UTF-8 ",
    "<wait>country=US keymap=us ",
    "<wait>hostname=tartarus domain=local ",
    "<enter><wait>",
  ]
  communicator     = "ssh"
  ssh_username     = "debian"
  ssh_password     = "debian"
  ssh_wait_timeout = "35m"
}

build {
  sources = ["source.proxmox-iso.tartarus_debian12"]
  provisioner "shell" {
    execute_command = "echo 'debian' | sudo -S sh -c '{{ .Vars }} {{ .Path }}'"
    inline = [
      "apt-get update",
      "DEBIAN_FRONTEND=noninteractive apt-get install -y python3 qemu-guest-agent sudo auditd audispd-plugins jq rsync curl strace gdbserver bpftrace lsof openssl unzip iproute2 iputils-ping netcat-openbsd",
      "install -d -m 0755 /var/cache/tartarus",
      "curl -fL --retry 5 -o /var/cache/tartarus/elasticsearch-9.5.5-amd64.deb https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-9.5.5-amd64.deb",
      "curl -fL --retry 5 -o /var/cache/tartarus/kibana-9.5.5-amd64.deb https://artifacts.elastic.co/downloads/kibana/kibana-9.5.5-amd64.deb",
      "curl -fL --retry 5 -o /var/cache/tartarus/elastic-agent-9.5.5-amd64.deb https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.5.5-amd64.deb",
      "apt-get clean",
      "truncate -s 0 /etc/machine-id",
      "printf '%s\\n' '[Unit]' 'Description=Generate unique SSH host keys on first boot' 'Before=ssh.service' 'ConditionPathExists=!/etc/ssh/ssh_host_ed25519_key' '' '[Service]' 'Type=oneshot' 'ExecStart=/usr/bin/ssh-keygen -A' '' '[Install]' 'WantedBy=multi-user.target' > /etc/systemd/system/tartarus-ssh-host-keys.service",
      "systemctl enable tartarus-ssh-host-keys.service",
      "rm -f /etc/ssh/ssh_host_*",
      "cloud-init clean --logs 2>/dev/null || true"
    ]
  }
}
