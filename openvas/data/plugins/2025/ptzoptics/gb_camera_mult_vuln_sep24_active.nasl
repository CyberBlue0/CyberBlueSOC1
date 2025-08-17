# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:ptzoptics:";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155079");
  script_version("2025-08-01T15:45:48+0000");
  script_tag(name:"last_modification", value:"2025-08-01 15:45:48 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-01 06:37:41 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-01 17:49:25 +0000 (Tue, 01 Oct 2024)");

  script_cve_id("CVE-2024-8956", "CVE-2024-8957");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PTZOptics Camera Multiple Vulnrebilities (Sep 2024) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ptzoptics_camera_http_detect.nasl");
  script_mandatory_keys("ptzoptics/camera/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"PTZOptics Camera devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-8956: Insufficient authentication

  - CVE-2024-8957: OS command injection");

  script_tag(name:"affected", value:"PTZOptics PT30X-SDI/NDI-xx devices are known to be affected.
  Other models might be affected as well.");

  script_tag(name:"solution", value:"Contact the vendor for a solution.");

  script_xref(name:"URL", value:"https://vulncheck.com/advisories/ptzoptics-insufficient-auth");
  script_xref(name:"URL", value:"https://vulncheck.com/advisories/ptzoptics-command-injection");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www", first_cpe_only: TRUE))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

url = "/cgi-bin/param.cgi?get_system_conf";

if (http_vuln_check(port: port, url: url, pattern: 'userpasswd="[a-f0-9]+"', check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0); # There might be other endpoints not fixed
