# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843250");
  script_cve_id("CVE-2014-9900", "CVE-2015-8944", "CVE-2015-8955", "CVE-2015-8962", "CVE-2015-8963", "CVE-2015-8964", "CVE-2015-8966", "CVE-2015-8967", "CVE-2016-10088", "CVE-2017-1000380", "CVE-2017-7346", "CVE-2017-7895", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9605");
  script_tag(name:"creation_date", value:"2017-07-22 05:25:26 +0000 (Sat, 22 Jul 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3360-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3360-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3360-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta' package(s) announced via the USN-3360-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Linux kernel did not properly initialize a Wake-
on-Lan data structure. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2014-9900)

It was discovered that the Linux kernel did not properly restrict access to
/proc/iomem. A local attacker could use this to expose sensitive
information. (CVE-2015-8944)

It was discovered that a use-after-free vulnerability existed in the
performance events and counters subsystem of the Linux kernel for ARM64. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2015-8955)

It was discovered that the SCSI generic (sg) driver in the Linux kernel
contained a double-free vulnerability. A local attacker could use this to
cause a denial of service (system crash). (CVE-2015-8962)

Sasha Levin discovered that a race condition existed in the performance
events and counters subsystem of the Linux kernel when handling CPU unplug
events. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2015-8963)

Tilman Schmidt and Sasha Levin discovered a use-after-free condition in the
TTY implementation in the Linux kernel. A local attacker could use this to
expose sensitive information (kernel memory). (CVE-2015-8964)

It was discovered that the fcntl64() system call in the Linux kernel did
not properly set memory limits when returning on 32-bit ARM processors. A
local attacker could use this to gain administrative privileges.
(CVE-2015-8966)

It was discovered that the system call table for ARM 64-bit processors in
the Linux kernel was not write-protected. An attacker could use this in
conjunction with another kernel vulnerability to execute arbitrary code.
(CVE-2015-8967)

It was discovered that the generic SCSI block layer in the Linux kernel did
not properly restrict write operations in certain situations. A local
attacker could use this to cause a denial of service (system crash) or
possibly gain administrative privileges. (CVE-2016-10088)

Alexander Potapenko discovered a race condition in the Advanced Linux Sound
Architecture (ALSA) subsystem in the Linux kernel. A local attacker could
use this to expose sensitive information (kernel memory).
(CVE-2017-1000380)

Li Qiang discovered that the DRM driver for VMware Virtual GPUs in the
Linux kernel did not properly validate some ioctl arguments. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-7346)

Tuomas Haanpaa and Ari Kauppi discovered that the NFSv2 and NFSv3 server
implementations in the Linux kernel did not properly check for the end of
buffer. A remote attacker could use this to craft requests that cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2017-7895)

It was discovered that an integer underflow existed in the Edgeport USB
Serial ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-meta' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
