# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843461");
  script_cve_id("CVE-2017-0750", "CVE-2017-0861", "CVE-2017-1000407", "CVE-2017-12153", "CVE-2017-12190", "CVE-2017-12192", "CVE-2017-14051", "CVE-2017-14140", "CVE-2017-14156", "CVE-2017-14489", "CVE-2017-15102", "CVE-2017-15115", "CVE-2017-15274", "CVE-2017-15868", "CVE-2017-16525", "CVE-2017-17450", "CVE-2017-17806", "CVE-2017-18017", "CVE-2017-5669", "CVE-2017-5754", "CVE-2017-7542", "CVE-2017-7889", "CVE-2017-8824", "CVE-2018-5333", "CVE-2018-5344");
  script_tag(name:"creation_date", value:"2018-02-24 08:03:42 +0000 (Sat, 24 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 20:40:00 +0000 (Fri, 22 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-3583-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3583-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3583-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta' package(s) announced via the USN-3583-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that an out-of-bounds write vulnerability existed in the
Flash-Friendly File System (f2fs) in the Linux kernel. An attacker could
construct a malicious file system that, when mounted, could cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2017-0750)

It was discovered that a race condition leading to a use-after-free
vulnerability existed in the ALSA PCM subsystem of the Linux kernel. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2017-0861)

It was discovered that the KVM implementation in the Linux kernel allowed
passthrough of the diagnostic I/O port 0x80. An attacker in a guest VM
could use this to cause a denial of service (system crash) in the host OS.
(CVE-2017-1000407)

Bo Zhang discovered that the netlink wireless configuration interface in
the Linux kernel did not properly validate attributes when handling certain
requests. A local attacker with the CAP_NET_ADMIN could use this to cause a
denial of service (system crash). (CVE-2017-12153)

Vitaly Mayatskikh discovered that the SCSI subsystem in the Linux kernel
did not properly track reference counts when merging buffers. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2017-12190)

It was discovered that the key management subsystem in the Linux kernel did
not properly restrict key reads on negatively instantiated keys. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-12192)

It was discovered that an integer overflow existed in the sysfs interface
for the QLogic 24xx+ series SCSI driver in the Linux kernel. A local
privileged attacker could use this to cause a denial of service (system
crash). (CVE-2017-14051)

Otto Ebeling discovered that the memory manager in the Linux kernel did not
properly check the effective UID in some situations. A local attacker could
use this to expose sensitive information. (CVE-2017-14140)

It was discovered that the ATI Radeon framebuffer driver in the Linux
kernel did not properly initialize a data structure returned to user space.
A local attacker could use this to expose sensitive information (kernel
memory). (CVE-2017-14156)

ChunYu Wang discovered that the iSCSI transport implementation in the Linux
kernel did not properly validate data structures. A local attacker could
use this to cause a denial of service (system crash). (CVE-2017-14489)

James Patrick-Evans discovered a race condition in the LEGO USB Infrared
Tower driver in the Linux kernel. A physically proximate attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-15102)

ChunYu Wang discovered that a use-after-free vulnerability existed in the
SCTP protocol implementation in the Linux kernel. A local attacker could
use this to cause a denial of service (system ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-meta' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
