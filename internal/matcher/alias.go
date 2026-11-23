package matcher

import "strings"

// Nmap and NVD disagree about vendor names for many products (the spike found
// nginx and Redis returned zero CVEs until remapped). Each entry maps an Nmap
// "vendor:product" to the NVD "vendor:product" pairs to query.
var aliases = map[string][][2]string{
	"igor_sysoev:nginx":                 {{"f5", "nginx"}, {"nginx", "nginx"}},
	"nginx:nginx":                       {{"f5", "nginx"}, {"nginx", "nginx"}},
	"redislabs:redis":                   {{"redis", "redis"}},
	"vsftpd:vsftpd":                     {{"vsftpd_project", "vsftpd"}, {"beasts", "vsftpd"}},
	"beasts:vsftpd":                     {{"vsftpd_project", "vsftpd"}, {"beasts", "vsftpd"}},
	"mysql:mysql":                       {{"oracle", "mysql"}, {"mysql", "mysql"}},
	"oracle:mysql":                      {{"oracle", "mysql"}},
	"microsoft:iis":                     {{"microsoft", "internet_information_services"}},
	"elasticsearch:elasticsearch":       {{"elastic", "elasticsearch"}},
	"jquery:jquery":                     {{"jquery", "jquery"}},
	"squid-cache:squid":                 {{"squid-cache", "squid"}},
	"dropbear_ssh_project:dropbear_ssh": {{"dropbear_ssh_project", "dropbear_ssh"}},
	"samba:samba":                       {{"samba", "samba"}},
	"proftpd:proftpd":                   {{"proftpd", "proftpd"}},
	"openbsd:openssh":                   {{"openbsd", "openssh"}},
	"apache:http_server":                {{"apache", "http_server"}},
	"apache:tomcat":                     {{"apache", "tomcat"}},
	"eclipse:jetty":                     {{"eclipse", "jetty"}},
	"postgresql:postgresql":             {{"postgresql", "postgresql"}},
	"isc:bind":                          {{"isc", "bind"}},
	"haproxy:haproxy":                   {{"haproxy", "haproxy"}},
	"lighttpd:lighttpd":                 {{"lighttpd", "lighttpd"}},
	"exim:exim":                         {{"exim", "exim"}},
	"postfix:postfix":                   {{"postfix", "postfix"}},
	"dovecot:dovecot":                   {{"dovecot", "dovecot"}},
}

// productNames maps an Nmap product string to a CPE vendor:product, used only
// when Nmap reports a version but no CPE.
var productNames = map[string]string{
	"apache httpd":                    "apache:http_server",
	"apache tomcat":                   "apache:tomcat",
	"apache tomcat/coyote jsp engine": "apache:tomcat",
	"openssh":                         "openbsd:openssh",
	"nginx":                           "f5:nginx",
	"vsftpd":                          "beasts:vsftpd",
	"redis key-value store":           "redislabs:redis",
	"redis":                           "redislabs:redis",
	"proftpd":                         "proftpd:proftpd",
	"microsoft iis httpd":             "microsoft:iis",
	"mysql":                           "mysql:mysql",
	"mariadb":                         "mariadb:mariadb",
	"postgresql db":                   "postgresql:postgresql",
	"postfix smtpd":                   "postfix:postfix",
	"exim smtpd":                      "exim:exim",
	"dovecot imapd":                   "dovecot:dovecot",
	"lighttpd":                        "lighttpd:lighttpd",
	"haproxy":                         "haproxy:haproxy",
	"mongodb":                         "mongodb:mongodb",
	"memcached":                       "memcached:memcached",
	"elasticsearch":                   "elasticsearch:elasticsearch",
	"samba smbd":                      "samba:samba",
	"isc bind":                        "isc:bind",
	"squid http proxy":                "squid-cache:squid",
}

// Candidates returns the NVD (vendor, product) pairs to query for an Nmap
// vendor/product, always including the pair itself.
func Candidates(vendor, product string) [][2]string {
	key := strings.ToLower(vendor) + ":" + strings.ToLower(product)
	out := [][2]string{{strings.ToLower(vendor), strings.ToLower(product)}}
	for _, a := range aliases[key] {
		dup := false
		for _, o := range out {
			if o == a {
				dup = true
			}
		}
		if !dup {
			out = append(out, a)
		}
	}
	return out
}
