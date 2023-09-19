package main

import (
	"io/ioutil"
	"log"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func loadBlockedDomains(filename string) ([]string, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return lines, nil
}

// 修改本地 hosts 文件
// func updateHostsFile(domain string) error {
// }

func main() {
	blockedDomains, err := loadBlockedDomains("blockHost.txt")
	if err != nil {
		log.Fatal("读取 blockHost.txt 出错: ", err)
	}

	// 修改本地 hosts 文件

	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("port 53")
	if err != nil {
		log.Fatal("设置 BPF 过滤器失败:", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns, ok := dnsLayer.(*layers.DNS)
			if !ok {
				log.Println("无法将数据转换为 DNS 类型")
				continue
			}
			for _, q := range dns.Questions {
				domain := string(q.Name)
				if contains(blockedDomains, domain) {
					//输出告警
					log.Printf("有一个程序正在解析黑域名中的域名: %s\n", domain)
				} else {
					log.Printf("有一个程序解析的域名是: %s\n", domain)
				}
			}
		}
	}
}

func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}
