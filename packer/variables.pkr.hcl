variable "version" {
  type        = string
  description = "Zentryc version (read from __version__.py)"
  default     = "3.0.0"
}

variable "iso_url" {
  type        = string
  description = "Ubuntu 24.04 Server ISO URL"
  default     = "https://releases.ubuntu.com/24.04/ubuntu-24.04.1-live-server-amd64.iso"
}

variable "iso_checksum" {
  type        = string
  description = "SHA256 checksum of the ISO"
  default     = "sha256:e240e4b801f7bb68c20d1356b60571d7c4f2b17e4e15e50c5bba02dcb1fb8e58"
}

variable "disk_size" {
  type        = string
  description = "VM disk size"
  default     = "40G"
}

variable "memory" {
  type        = number
  description = "VM RAM in MB"
  default     = 4096
}

variable "cpus" {
  type        = number
  description = "VM CPU count"
  default     = 2
}

variable "headless" {
  type        = bool
  description = "Run build headless (no GUI)"
  default     = true
}

variable "compiled_tarball" {
  type        = string
  description = "Path to the compiled Zentryc tarball"
  default     = "../build/output/zentryc-3.0.0-compiled.tar.gz"
}

variable "output_dir" {
  type        = string
  description = "Output directory for built images"
  default     = "output"
}
