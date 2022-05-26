/**
 * @Description
 * @Author r0cky
 * @Date 2021/12/22 14:45
 **/
package dns

var (
	Server *DnslogServer
)

type DnslogServer struct {
	*Interactsh
	*Dnslog
	*Ceye
}

func NewServer() *DnslogServer {
	return &DnslogServer{
		Interactsh: &Interactsh{},
		Dnslog:     &Dnslog{},
		Ceye:       &Ceye{},
	}
}

func (d *DnslogServer) GetDomain() string {
	if d.Interactsh.state {
		return d.Interactsh.GetDomain()
	} else if d.Ceye.state {
		return d.Ceye.GetDomain()
	} else if d.Dnslog.state {
		return d.Dnslog.GetDomain()
	}
	return ""
}

func (d *DnslogServer) CheckDnslog(domain string) bool {
	if d.Ceye.state {
		return d.Ceye.CheckDnslog(domain)
	} else if d.Dnslog.state {
		return d.Dnslog.CheckDnslog(domain)
	}
	return false
}
