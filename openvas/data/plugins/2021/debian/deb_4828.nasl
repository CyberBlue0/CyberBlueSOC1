# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704828");
  script_cve_id("CVE-2020-26258", "CVE-2020-26259");
  script_tag(name:"creation_date", value:"2021-01-09 04:00:09 +0000 (Sat, 09 Jan 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-13 18:14:00 +0000 (Tue, 13 Apr 2021)");

  script_name("Debian: Security Advisory (DSA-4828)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4828");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4828");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libxstream-java");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxstream-java' package(s) announced via the DSA-4828 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Liaogui Zhong discovered two security issues in XStream, a Java library to serialise objects to XML and back again, which could result in the deletion of files or server-side request forgery when unmarshalling.

For the stable distribution (buster), these problems have been fixed in version 1.4.11.1-1+deb10u2.

We recommend that you upgrade your libxstream-java packages.

For the detailed security status of libxstream-java please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libxstream-java' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);