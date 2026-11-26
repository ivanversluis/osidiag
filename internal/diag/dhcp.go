package diag

// DHCPOnly reads the lease metadata already obtained by the L2 platform
// backend. It sends no DHCPDISCOVER and never renews a lease.
func DHCPOnly(o Options) Result {
	neighbor := Neighbors(o)
	data := map[string]any{
		"read_only": true,
		"note": "DHCP lease metadata is an OS snapshot; no server response was verified.",
	}
	if neighbor.Data == nil {
		return result(2, "DHCP", Warn, "DHCP lease metadata unavailable", data, nil)
	}
	for _, key := range []string{"interface", "index", "default_gateway", "dhcp_note", "dhcp_lookup_note"} {
		if value, found := neighbor.Data[key]; found {
			data[key] = value
		}
	}
	raw, present := neighbor.Data["dhcp"]
	if !present {
		return result(2, "DHCP", Warn, "DHCP lease metadata not available on this platform", data, nil)
	}
	data["dhcp"] = raw
	lease, valid := raw.(map[string]any)
	if !valid {
		return result(2, "DHCP", Warn, "DHCP metadata format unrecognized", data, nil)
	}
	enabled, found := lease["enabled"].(bool)
	if !found { enabled, found = lease["DHCPEnabled"].(bool) }
	if !found {
		return result(2, "DHCP", Warn, "DHCP administrative status unknown", data, nil)
	}
	if !enabled {
		return result(2, "DHCP", Warn, "DHCP disabled on selected adapter", data, nil)
	}
	server, _ := lease["server"].(string)
	if server == "" { server, _ = lease["DHCPServer"].(string) }
	if server == "" {
		return result(2, "DHCP", Warn, "DHCP enabled but server address not recorded", data, nil)
	}
	return result(2, "DHCP", OK, "DHCP server recorded in local lease (not actively verified)", data, nil)
}
